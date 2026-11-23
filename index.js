import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import "dotenv/config";
import cors from "cors";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
const port = process.env.PORT || 4000;

//midleware
app.use(cors({
    origin(origin, callback) {
        if (!origin || /^http:\/\/(localhost|127\.0\.0\.1):3000$/.test(origin)) {
            return callback(null, true);
        }
        return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());
app.use((error, req, res, next) => {
    if (error instanceof SyntaxError && "body" in error) {
        return res.status(400).json({ error: "Invalid JSON body." });
    }
    return next(error);
});
const client = new MongoClient(`mongodb://${process.env.DB_USER}:${process.env.DB_PASSWORD}@ac-gewkcdw-shard-00-00.tlv5tmv.mongodb.net:27017,ac-gewkcdw-shard-00-01.tlv5tmv.mongodb.net:27017,ac-gewkcdw-shard-00-02.tlv5tmv.mongodb.net:27017/?ssl=true&replicaSet=atlas-6gpape-shard-0&authSource=admin`);

export async function connectToMongoDB() {
    await client.connect();
    console.log("You successfully connected to MongoDB!");
    return client;
}

let connectedClient;
try {
    connectedClient = await connectToMongoDB();
} catch (error) {
    console.error("Unable to start MentorLagbe backend: MongoDB is unavailable.", error);
    process.exit(1);
}
const database = connectedClient.db("mentorlagbe");
const user = database.collection("user");
const tution = database.collection("tution");
const session = database.collection("session");
// Plans live separately so the existing user collection is never changed.
const tutorPlan = database.collection("tutorPlan");
// Student applications are stored separately from tuition posts.
const application = database.collection("application");
// Student bookmarks are stored separately; one bookmark per student per tuition.
const bookmark = database.collection("bookmark");

// One application per student per tuition, even if two requests arrive together.
// If legacy duplicates exist, log the problem but keep the server available.
try {
    await application.createIndex(
        { studentId: 1, tuitionId: 1 },
        { unique: true, name: "studentId_1_tuitionId_1" }
    );
} catch (error) {
    console.error("Unable to create application unique index:", error);
}

try {
    await bookmark.createIndex(
        { studentId: 1, tuitionId: 1 },
        { unique: true, name: "studentId_1_tuitionId_1" }
    );
} catch (error) {
    console.error("Unable to create bookmark unique index:", error);
}

const FREE_POST_LIMIT = 2;
const FREE_BOOKMARK_LIMIT = 5;

const AUTH_BASE_URL = (process.env.BETTER_AUTH_URL || "http://localhost:3000").replace(/\/+$/, "");
const AUTH_JWKS_URL = process.env.BETTER_AUTH_JWKS_URL || `${AUTH_BASE_URL}/api/auth/jwks`;
const AUTH_ISSUER = process.env.BETTER_AUTH_JWT_ISSUER || AUTH_BASE_URL;
const AUTH_AUDIENCE = process.env.BETTER_AUTH_JWT_AUDIENCE || AUTH_BASE_URL;
const JWKS = createRemoteJWKSet(new URL(AUTH_JWKS_URL));

function parseCookies(cookieHeader = "") {
    const cookies = Object.create(null);

    for (const part of cookieHeader.split(";")) {
        const separatorIndex = part.indexOf("=");
        if (separatorIndex < 0) continue;

        const name = part.slice(0, separatorIndex).trim();
        let value = part.slice(separatorIndex + 1).trim();

        try {
            value = decodeURIComponent(value);
        } catch {
            // Keep the raw value if it is not URL encoded.
        }

        cookies[name] = value;
    }

    return cookies;
}

/* Better Auth signs the session token with HMAC-SHA256 using BETTER_AUTH_SECRET. */
function getSignedSessionToken(req) {
    const secret = process.env.BETTER_AUTH_SECRET;
    if (!secret) {
        throw new Error("BETTER_AUTH_SECRET is not configured on the server.");
    }

    const signedCookie = parseCookies(req.headers.cookie)["better-auth.session_token"];
    if (!signedCookie) return null;

    const signatureStart = signedCookie.lastIndexOf(".");
    if (signatureStart < 1) return null;

    const token = signedCookie.slice(0, signatureStart);
    const signature = signedCookie.slice(signatureStart + 1);
    if (signature.length !== 44 || !signature.endsWith("=")) return null;

    const expectedSignature = createHmac("sha256", secret).update(token).digest("base64");
    const providedBuffer = Buffer.from(signature);
    const expectedBuffer = Buffer.from(expectedSignature);

    if (
        providedBuffer.length !== expectedBuffer.length ||
        !timingSafeEqual(providedBuffer, expectedBuffer)
    ) {
        return null;
    }

    return token;
}

async function getUserById(userId) {
    if (!/^[0-9a-fA-F]{24}$/.test(userId) || !ObjectId.isValid(userId)) {
        return null;
    }

    let account;
    try {
        account = await user.findOne(
            { _id: new ObjectId(userId) },
            { projection: { name: 1, email: 1, role: 1 } }
        );
    } catch {
        return null;
    }

    if (!account) return null;

    return {
        userId: String(account._id),
        name: cleanText(account.name),
        email: cleanText(account.email),
        role: cleanText(account.role),
    };
}

/* Shared Better Auth session verification. Never trust frontend-supplied
   userId/email/role; identity and role come from the verified session + DB. */
async function getVerifiedSessionUser(req) {
    const token = getSignedSessionToken(req);
    if (!token) return null;

    const activeSession = await session.findOne({ token });
    if (!activeSession) return null;

    const expiresAt = new Date(activeSession.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
        return null;
    }

    return getUserById(String(activeSession.userId));
}

function getBearerToken(req) {
    const header = req.headers.authorization;
    if (typeof header !== "string" || !header.trim()) {
        return { kind: "none" };
    }

    const [scheme, ...rest] = header.trim().split(/\s+/);
    if (scheme !== "Bearer" || rest.length !== 1 || !rest[0]) {
        return { kind: "invalid" };
    }

    return { kind: "bearer", token: rest[0] };
}

async function getVerifiedJwtUser(req) {
    const bearer = getBearerToken(req);
    if (bearer.kind === "none") return { kind: "none" };
    if (bearer.kind === "invalid") return { kind: "invalid" };

    let payload;
    try {
        ({ payload } = await jwtVerify(bearer.token, JWKS, {
            issuer: AUTH_ISSUER,
            audience: AUTH_AUDIENCE,
        }));
    } catch {
        return { kind: "invalid" };
    }

    const sub = typeof payload.sub === "string" ? payload.sub.trim() : "";
    if (!sub) return { kind: "invalid" };

    // Current role always comes from MongoDB, never from JWT claims.
    const account = await getUserById(sub);
    if (!account) return { kind: "invalid" };

    return { kind: "ok", user: account };
}

async function authenticateRequest(req) {
    if (req.user) return { ok: true, user: req.user };

    const bearer = getBearerToken(req);
    if (bearer.kind !== "none") {
        const jwtUser = await getVerifiedJwtUser(req);
        if (jwtUser.kind === "ok") return { ok: true, user: jwtUser.user };
        return {
            ok: false,
            status: 401,
            error: "Unauthorized: missing or invalid authentication.",
        };
    }

    // Backward-compatible cookie fallback for existing session-based clients.
    const sessionUser = await getVerifiedSessionUser(req);
    if (sessionUser) return { ok: true, user: sessionUser };

    return {
        ok: false,
        status: 401,
        error: "Unauthorized: missing or invalid authentication.",
    };
}

async function verifyToken(req, res, next) {
    try {
        const authResult = await authenticateRequest(req);
        if (!authResult.ok) {
            return res.status(authResult.status).json({ error: authResult.error });
        }
        req.user = authResult.user;
        return next();
    } catch (error) {
        console.error("verifyToken failed:", error);
        return res.status(500).json({ error: "Authentication failed." });
    }
}

function verifyRole(requiredRole) {
    return async (req, res, next) => {
        try {
            const authResult = await authenticateRequest(req);
            if (!authResult.ok) {
                return res.status(authResult.status).json({ error: authResult.error });
            }
            req.user = authResult.user;

            if (req.user.role !== requiredRole) {
                return res.status(403).json({ error: "Forbidden: insufficient role." });
            }

            return next();
        } catch (error) {
            console.error(`verifyRole(${requiredRole}) failed:`, error);
            return res.status(500).json({ error: "Authorization failed." });
        }
    };
}

async function verifyStudent(req, res, next) {
    return verifyRole("student")(req, res, next);
}

async function verifyTutor(req, res, next) {
    return verifyRole("tutor")(req, res, next);
}

async function verifyAdmin(req, res, next) {
    return verifyRole("admin")(req, res, next);
}

// Backward-compatible helpers for any remaining internal use.
async function getAuthenticatedTutor(req) {
    const authResult = await authenticateRequest(req);
    const verifiedUser = authResult.ok ? authResult.user : null;
    if (!verifiedUser || verifiedUser.role !== "tutor") return null;
    return { userId: verifiedUser.userId, name: verifiedUser.name, email: verifiedUser.email };
}

async function getAuthenticatedUser(req) {
    const authResult = await authenticateRequest(req);
    return authResult.ok ? authResult.user : null;
}

function cleanText(value) {
    return typeof value === "string" ? value.trim() : "";
}

function toIsoString(value) {
    const date = new Date(value);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

function isValidBannerImageUrl(value) {
    try {
        const url = new URL(value);
        return (url.protocol === "http:" || url.protocol === "https:") && Boolean(url.hostname);
    } catch {
        return false;
    }
}

function validateTuition(body, requireBannerImage = true) {
    const errors = [];

    const title = cleanText(body.title);
    const subject = cleanText(body.subject);
    const classLevel = cleanText(body.classLevel);
    const mode = cleanText(body.mode);
    const description = cleanText(body.description);
    const bannerImage = cleanText(body.bannerImage);

    if (!title) errors.push("Title is required.");
    if (!subject) errors.push("Subject is required.");
    if (!classLevel) errors.push("Class level is required.");
    if (mode !== "online" && mode !== "offline") {
        errors.push("Mode must be online or offline.");
    }

    const location = mode === "online" ? "Online" : cleanText(body.location);
    if (mode === "offline" && !location) {
        errors.push("Location is required for offline tuitions.");
    }

    const monthlyFee = Number(body.monthlyFee);
    if (!Number.isFinite(monthlyFee) || monthlyFee <= 0) {
        errors.push("Monthly fee must be greater than 0.");
    }

    const daysPerWeek = Number(body.daysPerWeek);
    if (!Number.isInteger(daysPerWeek) || daysPerWeek < 1 || daysPerWeek > 7) {
        errors.push("Days per week must be between 1 and 7.");
    }

    if (!description) errors.push("Description is required.");
    if (requireBannerImage) {
        if (!bannerImage) {
            errors.push("Banner image is required.");
        } else if (!isValidBannerImageUrl(bannerImage)) {
            errors.push("Banner image must be a valid URL.");
        }
    }

    return {
        errors,
        value: {
            title,
            subject,
            classLevel,
            mode,
            location,
            monthlyFee,
            daysPerWeek,
            description,
            bannerImage,
        },
    };
}

app.get('/', (req, res) => {
    res.send('hello');
});

app.get('/users', async (req, res) => {
    const cursor = user.find({});
    const result = await cursor.toArray();
    res.send(result);

});

//tution post related api
// Tuition search API
app.get('/tution-post', async (req, res) => {
    try {
        const readQueryValue = (value) => {
            if (Array.isArray(value)) value = value[0];
            return typeof value === "string" ? value.trim() : "";
        };

        const query = {
            approvalStatus: "approved",
            isActive: true
        };

        const search = readQueryValue(req.query.search);
        const subject = readQueryValue(req.query.subject);
        const classLevel = readQueryValue(req.query.classLevel);
        const mode = readQueryValue(req.query.mode).toLowerCase();

        if (search) {
            const escapedSearch = search.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            query.$or = [
                {
                    title: {
                        $regex: escapedSearch,
                        $options: "i"
                    }
                },
                {
                    subject: {
                        $regex: escapedSearch,
                        $options: "i"
                    }
                }
            ];
        }

        if (subject) {
            const escapedSubject = subject.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            query.subject = { $regex: `^${escapedSubject}$`, $options: "i" };
        }
        if (classLevel) {
            const escapedClassLevel = classLevel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            query.classLevel = { $regex: `^${escapedClassLevel}$`, $options: "i" };
        }
        if (mode === "online" || mode === "offline") query.mode = mode;

        const result = await tution.find(query).toArray();

        res.status(200).send(result);

    } catch (error) {
        console.error("Search tuition failed:", error);
        res.status(500).send({
            error: "Failed to search tuitions."
        });
    }
});

// Tutor-scoped read used by the "My Tuitions" page.
app.get('/tution-post/my', verifyTutor, async (req, res) => {
    try {
        // Ownership comes only from the authenticated session. Match both the current
        // string tutorId and legacy ObjectId/email variants so older own posts are
        // not silently omitted. No approval, active, or tutor-status filter is used.
        const tutorId = String(req.user.userId);
        const ownerClauses = [{ tutorId }];

        if (ObjectId.isValid(tutorId)) {
            ownerClauses.push({ tutorId: new ObjectId(tutorId) });
        }

        const tutorEmail = cleanText(req.user.email);
        if (tutorEmail) {
            const escapedEmail = tutorEmail.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
            ownerClauses.push({
                tutorEmail: { $regex: `^${escapedEmail}$`, $options: "i" }
            });
        }

        const result = await tution.find({ $or: ownerClauses }).toArray();
        res.status(200).json(result);
    } catch (error) {
        console.error("GET /tution-post/my failed:", error);
        res.status(500).json({ error: "Failed to load tuitions." });
    }
});

// Public tuition details. Kept after /tution-post/my so "my" is not treated as an id.
app.get('/tution-post/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const isValidId = /^[0-9a-fA-F]{24}$/.test(id) && ObjectId.isValid(id);
        if (!isValidId) {
            return res.status(400).json({ error: "Invalid tuition ID." });
        }

        const doc = await tution.findOne({
            _id: new ObjectId(id),
            approvalStatus: "approved",
            isActive: true
        });

        if (!doc) {
            return res.status(404).json({ error: "Tuition not found." });
        }

        // Only public tutor fields are read and returned.
        const tutorId = String(doc.tutorId || "");
        let tutor = {
            name: cleanText(doc.tutorName) || "MentorLagbe Tutor",
            image: "",
            role: "tutor",
            joinedAt: null
        };

        if (/^[0-9a-fA-F]{24}$/.test(tutorId)) {
            const tutorDoc = await user.findOne(
                { _id: new ObjectId(tutorId) },
                { projection: { name: 1, image: 1, role: 1, createdAt: 1 } }
            );
            if (tutorDoc) {
                const image = cleanText(tutorDoc.image);
                tutor = {
                    name: cleanText(tutorDoc.name) || tutor.name,
                    image: isValidBannerImageUrl(image) ? image : "",
                    role: "tutor",
                    joinedAt: tutorDoc.createdAt || null
                };
            }
        }

        const mode = cleanText(doc.mode) === "offline" ? "offline" : "online";
        const monthlyFee = Number(doc.monthlyFee);
        const rawDays = Number(doc.daysPerWeek);
        const daysPerWeek =
            Number.isInteger(rawDays) && rawDays >= 1 && rawDays <= 7 ? rawDays : 1;
        const bannerImage = cleanText(doc.bannerImage);

        res.status(200).json({
            id: String(doc._id),
            title: cleanText(doc.title),
            subject: cleanText(doc.subject),
            classLevel: cleanText(doc.classLevel),
            mode,
            location: mode === "offline" ? cleanText(doc.location) : "Online",
            monthlyFee: Number.isFinite(monthlyFee) && monthlyFee > 0 ? monthlyFee : 0,
            daysPerWeek,
            schedule: `${daysPerWeek} ${daysPerWeek === 1 ? "day" : "days"} per week`,
            description: cleanText(doc.description),
            bannerImage: isValidBannerImageUrl(bannerImage) ? bannerImage : "",
            createdAt: doc.createdAt || null,
            tutor
        });
    } catch (error) {
        console.error("GET /tution-post/:id failed:", error);
        res.status(500).json({ error: "Failed to load tuition details." });
    }
});

// Student application. Identity and role always come from the verified session.
app.post('/tution-post/:id/apply', verifyStudent, async (req, res) => {
    try {
        const applicant = req.user;

        const { id } = req.params;
        const isValidId = /^[0-9a-fA-F]{24}$/.test(id) && ObjectId.isValid(id);
        if (!isValidId) {
            return res.status(400).json({ error: "Invalid tuition ID." });
        }

        const tuitionDoc = await tution.findOne(
            {
                _id: new ObjectId(id),
                approvalStatus: "approved",
                isActive: true
            },
            { projection: { title: 1, tutorEmail: 1, tutorId: 1 } }
        );
        if (!tuitionDoc) {
            return res.status(404).json({ error: "Tuition not found or no longer available." });
        }

        let tutorEmail = cleanText(tuitionDoc.tutorEmail);
        if (!tutorEmail) {
            const tutorId = cleanText(tuitionDoc.tutorId);
            if (/^[0-9a-fA-F]{24}$/.test(tutorId) && ObjectId.isValid(tutorId)) {
                const tutorAccount = await user.findOne(
                    { _id: new ObjectId(tutorId) },
                    { projection: { email: 1 } }
                );
                tutorEmail = cleanText(tutorAccount?.email);
            }
        }

        const phone = cleanText(req.body?.phone);
        const preferredSchedule = cleanText(req.body?.preferredSchedule);
        const learningNote = cleanText(req.body?.learningNote);

        const errors = [];
        if (!phone) errors.push("Phone is required.");
        else if (phone.length > 50) errors.push("Phone must be 50 characters or fewer.");
        if (!preferredSchedule) errors.push("Preferred schedule is required.");
        else if (preferredSchedule.length > 200) {
            errors.push("Preferred schedule must be 200 characters or fewer.");
        }
        if (learningNote.length > 2000) {
            errors.push("Learning note must be 2000 characters or fewer.");
        }
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(" ") });
        }

        const duplicate = await application.findOne({
            studentId: applicant.userId,
            tuitionId: id
        });
        if (duplicate) {
            return res.status(409).json({ error: "You have already applied for this tuition." });
        }

        // Store key application fields explicitly; tuition title remains joined on read.
        const applicationData = {
            tuitionId: id,
            tutorEmail,
            studentId: applicant.userId,
            studentName: applicant.name,
            studentEmail: applicant.email,
            phone,
            preferredSchedule,
            learningNote,
            status: "pending",
            createdAt: new Date()
        };

        let inserted;
        try {
            inserted = await application.insertOne(applicationData);
        } catch (error) {
            if (error && error.code === 11000) {
                return res.status(409).json({ error: "You have already applied for this tuition." });
            }
            throw error;
        }

        res.status(201).json({
            id: String(inserted.insertedId),
            ...applicationData,
            tuitionTitle: cleanText(tuitionDoc.title)
        });
    } catch (error) {
        console.error("POST /tution-post/:id/apply failed:", error);
        res.status(500).json({ error: "Failed to submit application." });
    }
});

// Applications belonging to the authenticated student, joined with live tuition data.
app.get('/application/my', verifyStudent, async (req, res) => {
    try {
        const student = req.user;

        const docs = await application
            .find(
                { studentId: student.userId },
                { sort: { createdAt: -1 } }
            )
            .toArray();
        const totalApplications = await application.countDocuments({
            studentId: student.userId
        });

        const tuitionIds = [
            ...new Set(
                docs
                    .map((doc) => String(doc.tuitionId || ""))
                    .filter((id) => /^[0-9a-fA-F]{24}$/.test(id))
            ),
        ];

        const tuitionDocs = tuitionIds.length
            ? await tution
                .find(
                    { _id: { $in: tuitionIds.map((id) => new ObjectId(id)) } },
                    {
                        projection: {
                            title: 1,
                            tutorName: 1,
                            tutorEmail: 1,
                            monthlyFee: 1,
                        },
                    }
                )
                .toArray()
            : [];
        const tuitionById = new Map(tuitionDocs.map((doc) => [String(doc._id), doc]));

        const applications = docs.map((doc) => {
            const tuitionId = String(doc.tuitionId || "");
            const tuition = tuitionById.get(tuitionId);
            const fee = Number(tuition?.monthlyFee);
            const status = cleanText(doc.status);

            return {
                id: String(doc._id),
                tuitionId,
                tuitionTitle: cleanText(tuition?.title) || "Tuition unavailable",
                tutorName: cleanText(tuition?.tutorName) || "Tutor information unavailable",
                tutorEmail: cleanText(tuition?.tutorEmail) || "Not provided",
                monthlyFee: Number.isFinite(fee) ? fee : 0,
                appliedDate: toIsoString(doc.createdAt),
                createdAt: toIsoString(doc.createdAt),
                status: status === "accepted" || status === "rejected" ? status : "pending",
                phone: cleanText(doc.phone),
                preferredSchedule: cleanText(doc.preferredSchedule),
                learningNote: cleanText(doc.learningNote),
            };
        });

        res.status(200).json({
            totalApplications,
            applications
        });
    } catch (error) {
        console.error("GET /application/my failed:", error);
        res.status(500).json({ error: "Failed to load applications." });
    }
});

// Students may cancel only their own pending applications.
app.delete('/application/:id', verifyStudent, async (req, res) => {
    try {
        const student = req.user;

        const { id } = req.params;
        if (!/^[0-9a-fA-F]{24}$/.test(id) || !ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid application ID." });
        }

        const objectId = new ObjectId(id);
        const existing = await application.findOne(
            { _id: objectId, studentId: student.userId },
            { projection: { status: 1 } }
        );
        if (!existing) {
            return res.status(404).json({ error: "Application not found." });
        }
        if (existing.status !== "pending") {
            return res.status(409).json({ error: "Only pending applications can be cancelled." });
        }

        const result = await application.deleteOne({
            _id: objectId,
            studentId: student.userId,
            status: "pending",
        });
        if (result.deletedCount === 0) {
            return res.status(409).json({ error: "Only pending applications can be cancelled." });
        }

        res.status(200).json({ message: "Application cancelled successfully." });
    } catch (error) {
        console.error("DELETE /application/:id failed:", error);
        res.status(500).json({ error: "Failed to cancel application." });
    }
});

// Returns bookmarked tuition IDs for the authenticated student.
app.get('/bookmarks/ids', verifyStudent, async (req, res) => {
    try {
        const student = req.user;
        const docs = await bookmark
            .find({ studentId: student.userId }, { projection: { tuitionId: 1, _id: 0 } })
            .toArray();
        res.status(200).json({
            tuitionIds: docs.map((doc) => String(doc.tuitionId || "")).filter(Boolean),
        });
    } catch (error) {
        console.error("GET /bookmarks/ids failed:", error);
        res.status(500).json({ error: "Failed to load bookmarks." });
    }
});

// Returns the authenticated student's bookmarked tuitions with live tuition data.
app.get('/bookmarks/my', verifyStudent, async (req, res) => {
    try {
        const student = req.user;
        const docs = await bookmark
            .find({ studentId: student.userId }, { sort: { createdAt: -1 } })
            .toArray();

        const tuitionIds = [
            ...new Set(
                docs
                    .map((doc) => String(doc.tuitionId || ""))
                    .filter((id) => /^[0-9a-fA-F]{24}$/.test(id) && ObjectId.isValid(id))
            ),
        ];

        const tuitionDocs = tuitionIds.length
            ? await tution
                .find(
                    { _id: { $in: tuitionIds.map((id) => new ObjectId(id)) } },
                    {
                        projection: {
                            title: 1,
                            subject: 1,
                            classLevel: 1,
                            mode: 1,
                            location: 1,
                            monthlyFee: 1,
                            daysPerWeek: 1,
                            description: 1,
                            bannerImage: 1,
                            tutorName: 1,
                            tutorEmail: 1,
                        },
                    }
                )
                .toArray()
            : [];
        const tuitionById = new Map(tuitionDocs.map((doc) => [String(doc._id), doc]));

        const bookmarks = docs.map((doc) => {
            const tuitionId = String(doc.tuitionId || "");
            const tuition = tuitionById.get(tuitionId);
            const mode = cleanText(tuition?.mode).toLowerCase() === "offline" ? "offline" : "online";
            const fee = Number(tuition?.monthlyFee);
            const days = Number(tuition?.daysPerWeek);

            return {
                id: String(doc._id),
                tuitionId,
                createdAt: toIsoString(doc.createdAt),
                tuition: tuition ? {
                    id: String(tuition._id),
                    title: cleanText(tuition.title) || "Untitled tuition",
                    subject: cleanText(tuition.subject),
                    classLevel: cleanText(tuition.classLevel),
                    mode,
                    location: mode === "online" ? "Online" : cleanText(tuition.location),
                    monthlyFee: Number.isFinite(fee) ? fee : 0,
                    daysPerWeek: Number.isInteger(days) && days >= 1 && days <= 7 ? days : 1,
                    description: cleanText(tuition.description),
                    bannerImage: cleanText(tuition.bannerImage),
                    tutorName: cleanText(tuition.tutorName),
                    tutorEmail: cleanText(tuition.tutorEmail),
                } : null,
            };
        });

        res.status(200).json({ bookmarks });
    } catch (error) {
        console.error("GET /bookmarks/my failed:", error);
        res.status(500).json({ error: "Failed to load bookmarks." });
    }
});

async function getUserPlanFromDb(userId) {
    if (!/^[0-9a-fA-F]{24}$/.test(userId) || !ObjectId.isValid(userId)) return "free";
    const account = await user.findOne(
        { _id: new ObjectId(userId) },
        { projection: { plan: 1 } }
    );
    return account?.plan === "pro" ? "pro" : "free";
}

// Student bookmark. Plan limit is enforced from the database, never from client input.
app.post('/bookmarks/:tuitionId', verifyStudent, async (req, res) => {
    try {
        const student = req.user;
        const { tuitionId } = req.params;
        if (!/^[0-9a-fA-F]{24}$/.test(tuitionId) || !ObjectId.isValid(tuitionId)) {
            return res.status(400).json({ error: "Invalid tuition ID." });
        }

        const tuitionDoc = await tution.findOne(
            { _id: new ObjectId(tuitionId) },
            { projection: { _id: 1 } }
        );
        if (!tuitionDoc) {
            return res.status(404).json({ error: "Tuition not found." });
        }

        const existing = await bookmark.findOne({ studentId: student.userId, tuitionId });
        if (existing) {
            return res.status(409).json({ error: "You have already bookmarked this tuition." });
        }

        const plan = await getUserPlanFromDb(student.userId);
        if (plan !== "pro") {
            const bookmarkCount = await bookmark.countDocuments({ studentId: student.userId });
            if (bookmarkCount >= FREE_BOOKMARK_LIMIT) {
                return res.status(403).json({
                    error: `Free plan allows a maximum of ${FREE_BOOKMARK_LIMIT} bookmarked tuitions. Upgrade to Pro for unlimited bookmarks.`,
                });
            }
        }

        const bookmarkData = {
            studentId: student.userId,
            tuitionId,
            createdAt: new Date(),
        };

        try {
            const inserted = await bookmark.insertOne(bookmarkData);
            if (plan !== "pro") {
                const totalAfterInsert = await bookmark.countDocuments({ studentId: student.userId });
                if (totalAfterInsert > FREE_BOOKMARK_LIMIT) {
                    await bookmark.deleteOne({ _id: inserted.insertedId, studentId: student.userId });
                    return res.status(403).json({
                        error: `Free plan allows a maximum of ${FREE_BOOKMARK_LIMIT} bookmarked tuitions. Upgrade to Pro for unlimited bookmarks.`,
                    });
                }
            }
            return res.status(201).json({ id: String(inserted.insertedId), ...bookmarkData });
        } catch (error) {
            if (error && error.code === 11000) {
                return res.status(409).json({ error: "You have already bookmarked this tuition." });
            }
            throw error;
        }
    } catch (error) {
        console.error("POST /bookmarks/:tuitionId failed:", error);
        res.status(500).json({ error: "Failed to bookmark tuition." });
    }
});

// Removes a bookmark owned by the authenticated student.
app.delete('/bookmarks/:tuitionId', verifyStudent, async (req, res) => {
    try {
        const student = req.user;
        const { tuitionId } = req.params;
        if (!/^[0-9a-fA-F]{24}$/.test(tuitionId) || !ObjectId.isValid(tuitionId)) {
            return res.status(400).json({ error: "Invalid tuition ID." });
        }

        const result = await bookmark.deleteOne({ studentId: student.userId, tuitionId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Bookmark not found." });
        }

        res.status(200).json({ message: "Bookmark removed successfully." });
    } catch (error) {
        console.error("DELETE /bookmarks/:tuitionId failed:", error);
        res.status(500).json({ error: "Failed to remove bookmark." });
    }
});

app.post('/tution-post', verifyTutor, async (req, res) => {
    try {
        const tutor = req.user;

        const { errors, value } = validateTuition(req.body || {});
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(" ") });
        }

        const planRecord = await tutorPlan.findOne({ userId: tutor.userId });
        const plan = planRecord?.plan === "pro" ? "pro" : "free";

        if (plan === "free") {
            const postCount = await tution.countDocuments({ tutorId: tutor.userId });
            if (postCount >= FREE_POST_LIMIT) {
                return res.status(403).json({
                    error: "Free plan allows a maximum of 2 tuition posts. Upgrade to Pro to post more.",
                });
            }
        }

        const now = new Date();
        const tutionData = {
            ...value,
            approvalStatus: "pending",
            tutorStatus: "active",
            isActive: true,
            tutorId: tutor.userId,
            tutorName: tutor.name,
            tutorEmail: tutor.email,
            postingPlan: plan,
            createdAt: now,
            updatedAt: now,
        };

        const result = await tution.insertOne(tutionData);
        res.status(201).json({ ...tutionData, _id: result.insertedId });
    } catch (error) {
        console.error("POST /tution-post failed:", error);
        res.status(500).json({ error: "Failed to save tuition. Please try again." });
    }
})
// Delete tuition post
app.delete('/tution-post/:id', verifyTutor, async (req, res) => {
    try {
        const tutor = req.user;

        const { id } = req.params;

        if (!ObjectId.isValid(id)) {
            return res.status(400).json({
                error: "Invalid tuition ID."
            });
        }

        const result = await tution.deleteOne({
            _id: new ObjectId(id),
            tutorId: tutor.userId
        });

        if (result.deletedCount === 0) {
            return res.status(404).json({
                error: "Tuition not found or you are not the owner."
            });
        }

        res.status(200).json({
            message: "Tuition post deleted successfully."
        });

    } catch (error) {
        console.error("Delete tuition failed:", error);

        res.status(500).json({
            error: "Failed to delete tuition."
        });
    }
});


app.patch('/tution-post/:id', verifyTutor, async (req, res) => {
    try {
        const tutor = req.user;

        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
            return res.status(400).json({ error: "Invalid tuition ID." });
        }

        const objectId = new ObjectId(id);
        const existing = await tution.findOne({
            _id: objectId,
            tutorId: tutor.userId
        });

        if (!existing) {
            return res.status(404).json({
                error: "Tuition not found or you are not the owner."
            });
        }

        const { errors, value } = validateTuition(
            { ...existing, ...req.body },
            false
        );
        if (errors.length > 0) {
            return res.status(400).json({ error: errors.join(" ") });
        }

        const { bannerImage: _bannerImage, ...updates } = value;
        await tution.updateOne(
            { _id: objectId, tutorId: tutor.userId },
            { $set: { ...updates, updatedAt: new Date() } }
        );

        res.send({ message: "Tuition updated successfully." });

    } catch (error) {
        console.error("Update tuition failed:", error);
        res.status(500).json({ error: "Failed to update tuition." });
    }
});

