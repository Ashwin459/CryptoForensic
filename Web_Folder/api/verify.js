import { MongoClient } from 'mongodb';
import crypto from 'crypto'; // Required for hashing

// We cache the client to prevent reconnecting on every request
let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
    if (cachedClient && cachedDb) {
        return { client: cachedClient, db: cachedDb };
    }

    // Get the URI from Vercel Environment Variables
    const uri = process.env.MONGODB_URI;

    if (!uri) {
        throw new Error('Please define the MONGODB_URI environment variable inside Vercel');
    }

    const client = new MongoClient(uri);
    await client.connect();

    // Connect to the specific database 'cft_db'
    const db = client.db('cft_db');

    cachedClient = client;
    cachedDb = db;

    return { client, db };
}

export default async function handler(req, res) {
    // Enable CORS
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    const { id } = req.query;

    // 1. Basic Input Validation
    if (!id) {
        return res.status(400).json({ error: "Missing Document ID" });
    }

    try {
        const { db } = await connectToDatabase();
        const collection = db.collection('assurance_letters');
        const logs = db.collection('verification_audit_logs'); // Audit Log Collection

        // 2. Fetch Document
        const doc = await collection.findOne({ internal_id: id });

        // --- SECURITY CHECK 1: DOCUMENT EXISTENCE ---
        if (!doc) {
            // Log the failed attempt
            await logs.insertOne({
                timestamp: new Date(),
                ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
                attempted_id: id,
                status: "FAILED_NOT_FOUND",
                user_agent: req.headers['user-agent']
            });
            return res.status(404).json({ error: "Document not found in registry" });
        }

        let status = "VALID";
        let message = "Document is active and authentic.";
        
        // --- NEW SECURITY CHECK: REVOCATION STATUS ---
        // This takes precedence over expiry. If revoked, it is invalid immediately.
        if (doc.revoked === true) {
            status = "REVOKED";
            message = "This document has been officially REVOKED by the issuer.";
        }
        else {
            // --- SECURITY CHECK 2: SERVER-SIDE EXPIRY ---
            // Only check expiry if the document is NOT revoked
            const today = new Date();
            today.setHours(0, 0, 0, 0); // Normalize today to midnight

            // Check if expiry is NOT "Lifetime" and NOT "N/A"
            if (doc.expiry_date && !doc.expiry_date.includes("Lifetime") && !doc.expiry_date.includes("N/A")) {
                // Parse "DD-MM-YYYY" from the database
                const parts = doc.expiry_date.split('-');
                if (parts.length === 3) {
                    // new Date(year, monthIndex, day)
                    const expDate = new Date(parts[2], parts[1] - 1, parts[0]);
                    
                    if (today > expDate) {
                        status = "EXPIRED";
                        message = `This document expired on ${doc.expiry_date}`;
                    }
                }
            }
        }

        // --- SECURITY CHECK 3: INTEGRITY HASHING ---
        // Create a unique fingerprint of the data. If DB data changes, hash changes.
        const recordString = `${doc.ref_no}|${doc.issued_to}|${doc.issue_date}|${doc.expiry_date}`;
        const integrityHash = crypto.createHash('sha256').update(recordString).digest('hex');

        // --- SECURITY CHECK 4: AUDIT LOGGING ---
        // Log the successful lookup (valid, expired, or revoked)
        await logs.insertOne({
            timestamp: new Date(),
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress,
            document_ref: doc.ref_no,
            result_status: status, // Logs "VALID", "EXPIRED", or "REVOKED"
            user_agent: req.headers['user-agent']
        });

        // 5. Return Response (Backend is the Authority)
        return res.status(200).json({
            status: status,       // Frontend obeys this ("VALID", "REVOKED", "EXPIRED")
            message: message,     
            integrity_hash: integrityHash,
            document: {
                ref_no: doc.ref_no,
                type: doc.type || "Document",
                issued_to: doc.issued_to,
                purpose: doc.purpose,
                issue_date: doc.issue_date,
                expiry_date: doc.expiry_date
            }
        });

    } catch (error) {
        console.error("Database Error:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
}
