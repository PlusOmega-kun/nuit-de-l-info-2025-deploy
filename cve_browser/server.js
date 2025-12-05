const express = require('express');
const cors = require('cors');
const { MongoClient } = require('mongodb');
const multer = require('multer'); // NEW: For file uploads
const xlsx = require('xlsx');     // NEW: For parsing Excel files

// --- Configuration ---
const PORT = process.env.PORT || 3000;
// Use environment variable for the cloud database connection string
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017'; 

const DB_NAME = 'cve_browser_db';
const COLLECTION_NAME = 'cves';

let db;
let cveCollection;

const app = express();
app.use(cors()); 
app.use(express.json()); 

// --- Configure Multer (Memory Storage) ---
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // Limit to 5MB
});

async function connectToMongo() {
    try {
        const client = new MongoClient(MONGO_URI);
        await client.connect();
        db = client.db(DB_NAME);
        cveCollection = db.collection(COLLECTION_NAME);
        console.log(`[MongoDB] Connected successfully to database: ${DB_NAME}`);
        
        // Ensure indexes
        await cveCollection.createIndex({ search_text: "text" }).catch(() => {});
        await cveCollection.createIndex({ 'cveMetadata.cveId': 1 }).catch(() => {});
        await cveCollection.createIndex({ 'cveMetadata.datePublished': -1 }).catch(() => {}); 
    } catch (error) {
        console.error("[MongoDB] Connection failed:", error.message);
        process.exit(1);
    }
}

// --- Helper to extract CVSS ---
const extractCvssScore = {
    $let: {
        vars: { metrics: { $ifNull: ["$containers.cna.metrics", []] } },
        in: {
            $reduce: {
                input: "$$metrics",
                initialValue: 0,
                in: {
                    $max: [
                        "$$value",
                        { $ifNull: ["$$this.cvssV3_1.baseScore", { $ifNull: ["$$this.cvssV3_0.baseScore", 0] }] }
                    ]
                }
            }
        }
    }
};

// --- API Endpoints ---

// 1. Search Endpoint
app.get('/api/cves', async (req, res) => {
    if (!cveCollection) return res.status(503).json({ error: 'Database service unavailable.' });

    try {
        const { search, limit, skip, sortField, sortOrder } = req.query;
        const limitVal = parseInt(limit) || 20;
        const skipVal = parseInt(skip) || 0;
        
        const pipeline = [];

        const term = search ? search.trim() : '';
        if (term && (term.toUpperCase().startsWith('CVE') || /\d{4}/.test(term))) {
            const regex = new RegExp(term.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&'), 'i');
            pipeline.push({ $match: { 'cveMetadata.cveId': regex } });
        } else if (term) {
            pipeline.push({ $match: { $text: { $search: term } } });
        } else {
            pipeline.push({ $match: {} });
        }

        pipeline.push({
            $addFields: {
                isValidDate: {
                    $cond: {
                        if: { 
                            $and: [
                                { $ne: ["$cveMetadata.datePublished", null] },
                                { $ne: ["$cveMetadata.datePublished", ""] },
                                { $gte: [{ $strLenCP: { $ifNull: ["$cveMetadata.datePublished", ""] } }, 4] } 
                            ]
                        },
                        then: 1, else: 0
                    }
                },
                extractedScore: extractCvssScore
            }
        });

        let sortStage = {};
        if (term && !term.toUpperCase().startsWith('CVE') && !/\d{4}/.test(term)) {
             sortStage = { score: { $meta: "textScore" } };
        } else if (sortField === 'date') {
            const dir = (sortOrder === 'asc' ? 1 : -1);
            sortStage = { isValidDate: -1, 'cveMetadata.datePublished': dir };
        } else if (sortField === 'id') {
            const dir = (sortOrder === 'asc' ? 1 : -1);
            sortStage = { 'cveMetadata.cveId': dir };
        } else {
            sortStage = { isValidDate: -1, 'cveMetadata.datePublished': -1 };
        }
        pipeline.push({ $sort: sortStage });
        
        pipeline.push({ $skip: skipVal });
        pipeline.push({ $limit: limitVal });
        pipeline.push({ $project: { isValidDate: 0 } });

        const results = await cveCollection.aggregate(pipeline).toArray();
        res.status(200).json(results);

    } catch (error) {
        console.error("Search Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// 2. Details Endpoint
app.get('/api/cves/:id', async (req, res) => {
    if (!cveCollection) return res.status(503).json({ error: 'Database service unavailable.' });
    try {
        const cveId = req.params.id.toUpperCase();
        const cve = await cveCollection.findOne({ 'cveMetadata.cveId': cveId });
        if (!cve) return res.status(404).json({ error: 'CVE not found' });
        res.status(200).json(cve);
    } catch (error) {
        console.error("Details Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// 3. Stats Endpoint
app.get('/api/stats', async (req, res) => {
    if (!cveCollection) return res.status(503).json({ error: 'Database service unavailable.' });

    try {
        const { search, duration } = req.query; 
        
        const pipeline = [];

        if (search && search.trim()) {
            pipeline.push({ $match: { $text: { $search: search.trim() } } });
        }

        if (duration) {
            const months = parseInt(duration);
            if (!isNaN(months) && months > 0) {
                const startDate = new Date();
                startDate.setMonth(startDate.getMonth() - months);
                pipeline.push({
                    $match: {
                        "cveMetadata.datePublished": { $gte: startDate.toISOString() }
                    }
                });
            }
        }

        pipeline.push({
            $addFields: {
                score: extractCvssScore,
                descText: { 
                    $reduce: {
                        input: "$containers.cna.descriptions",
                        initialValue: "",
                        in: { $concat: ["$$value", " ", { $ifNull: ["$$this.value", ""] }] }
                    }
                },
                month: { $substr: ["$cveMetadata.datePublished", 0, 7] } 
            }
        });

        pipeline.push({
            $facet: {
                topCvss: [
                    { $match: { score: { $gt: 0 } } },
                    { $sort: { score: -1 } },
                    { $limit: 10 },
                    { $project: { "cveMetadata.cveId": 1, score: 1, "cveMetadata.datePublished": 1 } }
                ],
                averages: [
                    { 
                        $group: { 
                            _id: null, 
                            avgCvss: { $avg: "$score" },
                            count: { $sum: 1 }
                        } 
                    }
                ],
                criticalCount: [
                    { $match: { score: { $gte: 9.0 } } },
                    { $count: "count" }
                ],
                exploitCount: [
                    { $match: { descText: { $regex: /exploit/i } } },
                    { $count: "count" }
                ],
                topCwes: [
                    { $unwind: "$containers.cna.problemTypes" },
                    { $unwind: "$containers.cna.problemTypes.descriptions" },
                    // --- FIX: Filter out N/A and similar garbage values ---
                    { 
                        $match: { 
                            "containers.cna.problemTypes.descriptions.description": { 
                                $nin: [null, "", "n/a", "N/A", "u'n/a'", "None", "unknown"] 
                            } 
                        } 
                    },
                    { 
                        $group: { 
                            _id: "$containers.cna.problemTypes.descriptions.description", 
                            count: { $sum: 1 } 
                        } 
                    },
                    { $sort: { count: -1 } },
                    { $limit: 5 }
                ],
                trend: [
                    { $match: { month: { $ne: "" } } },
                    { 
                        $group: { 
                            _id: "$month", 
                            avgScore: { $avg: "$score" },
                            count: { $sum: 1 }
                        } 
                    },
                    { $sort: { _id: 1 } } 
                ]
            }
        });

        const stats = await cveCollection.aggregate(pipeline).toArray();
        res.status(200).json(stats[0]);

    } catch (error) {
        console.error("Stats Error:", error);
        res.status(500).json({ error: error.message });
    }
});

// 4. File Upload Endpoint (NEW)
app.post('/api/upload', upload.single('file'), async (req, res) => {
    if (!cveCollection) return res.status(503).json({ error: 'Database service unavailable.' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    try {
        let textContent = '';
        const buffer = req.file.buffer;
        const originalName = req.file.originalname.toLowerCase();

        // 1. Parse File Content
        if (originalName.endsWith('.xlsx') || originalName.endsWith('.xls')) {
            // Excel Parsing
            const workbook = xlsx.read(buffer, { type: 'buffer' });
            workbook.SheetNames.forEach(sheetName => {
                const sheet = workbook.Sheets[sheetName];
                // Convert sheet to JSON structure to grab all text
                const sheetData = xlsx.utils.sheet_to_json(sheet);
                textContent += JSON.stringify(sheetData);
            });
        } else {
            // Text/CSV Parsing
            textContent = buffer.toString('utf8');
        }

        // 2. Extract CVE IDs using Regex
        const cveRegex = /CVE-\d{4}-\d{4,}/gi;
        const matches = textContent.match(cveRegex);

        if (!matches || matches.length === 0) {
            return res.json({ 
                foundCount: 0, 
                resolvedCount: 0, 
                cves: [], 
                message: "No CVE IDs found in the document." 
            });
        }

        // 3. Deduplicate
        const uniqueIds = [...new Set(matches.map(id => id.toUpperCase()))];

        // 4. Query DB for these IDs
        const foundCves = await cveCollection.find({ 
            'cveMetadata.cveId': { $in: uniqueIds } 
        }).toArray();

        // Sort by ID
        foundCves.sort((a, b) => b.cveMetadata.cveId.localeCompare(a.cveMetadata.cveId));

        res.json({
            foundCount: uniqueIds.length,
            resolvedCount: foundCves.length,
            cves: foundCves
        });

    } catch (error) {
        console.error("Upload Error:", error);
        res.status(500).json({ error: 'Failed to process file: ' + error.message });
    }
});

async function startServer() {
    await connectToMongo();
    app.listen(PORT, () => {
        console.log(`[Server] CVE API running on http://localhost:${PORT}`);
    });
}
startServer();