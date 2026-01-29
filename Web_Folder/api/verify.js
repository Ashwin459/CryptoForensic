import { MongoClient } from 'mongodb';

// We cache the client to prevent reconnecting on every request (Vercel optimization)
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

    // IMPORTANT: Using 'cft_db' to match the Python App
    const db = client.db('cft_db');

    cachedClient = client;
    cachedDb = db;

    return { client, db };
}

export default async function handler(req, res) {
    // Enable CORS so the HTML page can read this data
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');

    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }

    const { id } = req.query;

    if (!id) {
        return res.status(400).json({ error: "Missing Document ID" });
    }

    try {
        const { db } = await connectToDatabase();
        const collection = db.collection('assurance_letters');

        // Find the document by the unique internal_id
        const doc = await collection.findOne({ internal_id: id });

        return res.status(200).json({ document: doc });

    } catch (error) {
        console.error("Database Error:", error);
        return res.status(500).json({ error: "Internal Server Error" });
    }
}
