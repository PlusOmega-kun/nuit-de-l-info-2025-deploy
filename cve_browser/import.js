const { MongoClient } = require('mongodb');
const fs = require('fs/promises');
const path = require('path');

// --- Configuration ---
// The connection string for your local MongoDB instance.
const mongoUri = 'mongodb://localhost:27017'; 
const dbName = 'cve_browser_db';
const collectionName = 'cves';

// --- !!! UPDATED PATH BASED ON USER'S DIRECTORY STRUCTURE !!! ---
// This path points to the 'cves' folder which contains the year folders (2025, 2024, etc.).
// Use path.normalize for safety on Windows paths.
const DATA_DIR = path.normalize('C:/Users/shher/Desktop/nuit de l\'info (2025)/mitre-cve-database/cve-data/mitre/cves');
const BULK_CHUNK_SIZE = 5000; // Define chunk size for clarity

// --- Helper Functions ---

/**
 * Recursively reads a directory and returns an array of all file paths.
 * Filters specifically for .json files.
 * @param {string} dir - The directory to start searching from.
 * @returns {Promise<string[]>} - Array of full paths to JSON files.
 */
async function getJsonFiles(dir) {
    let files = [];
    
    // Check if the directory exists first
    try {
        await fs.access(dir);
    } catch (e) {
        console.error(`[ERROR] Data directory not found: ${dir}`);
        console.error(`Please check the DATA_DIR constant in import.js and ensure the path is correct: ${dir}`);
        return files;
    }

    const entries = await fs.readdir(dir, { withFileTypes: true });

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            // Recurse into subdirectories (e.g., /2025, /2024, or /0xxx, /1xxx inside 2025)
            files = files.concat(await getJsonFiles(fullPath));
        } else if (entry.isFile() && entry.name.endsWith('.json')) {
            // Found a CVE JSON file
            files.push(fullPath);
        }
    }
    return files;
}

/**
 * Main function to connect to MongoDB and import the data.
 */
async function importData() {
    let client;
    let successfulInserts = 0;
    let failedInserts = 0;

    console.log(`[START] Starting CVE data import...`);
    
    try {
        // 1. Connect to MongoDB
        client = new MongoClient(mongoUri);
        await client.connect();
        const db = client.db(dbName);
        const collection = db.collection(collectionName);

        console.log(`[DB] Successfully connected to MongoDB at ${mongoUri}`);

        // OPTIONAL: Clear the existing collection for a fresh import (if needed)
        console.log(`[DB] Dropping existing collection '${collectionName}'...`);
        // Use a safe drop to prevent errors if the collection doesn't exist
        await db.dropCollection(collectionName).catch(e => {
            if (e.codeName !== 'NamespaceNotFound' && e.message !== 'ns not found') throw e;
        }); 
        console.log(`[DB] Collection dropped (or did not exist). Starting fresh import.`);
        
        // 2. Locate Data
        console.log(`[FS] Scanning for JSON files in: ${DATA_DIR}`);
        const jsonFiles = await getJsonFiles(DATA_DIR);
        
        if (jsonFiles.length === 0) {
            console.log("[WARNING] No JSON files found. Please check the DATA_DIR path again.");
        }
        
        console.log(`[FS] Found ${jsonFiles.length} CVE files to process.`);
        
        // Prepare bulk operations for better performance
        let bulkOperations = []; // Use 'let' so we can reassign it

        // 3. Read & Parse
        for (const filePath of jsonFiles) {
            try {
                const fileContent = await fs.readFile(filePath, 'utf8');
                const cveRecord = JSON.parse(fileContent);
                
                // Add an indexable field containing all English descriptions for text search
                let fullText = '';
                if (cveRecord.containers?.cna?.descriptions) {
                    // Concatenate all English descriptions into one string
                    fullText = cveRecord.containers.cna.descriptions
                        .filter(d => d.lang === 'en')
                        .map(d => d.value)
                        .join(' ');
                }
                cveRecord.search_text = fullText;

                // 4. Queue the Insert Operation
                bulkOperations.push({
                    insertOne: {
                        document: cveRecord
                    }
                });
                
                // Execute bulk operation in chunks to manage memory
                if (bulkOperations.length >= BULK_CHUNK_SIZE) {
                    await collection.bulkWrite(bulkOperations, { ordered: false });
                    successfulInserts += bulkOperations.length;
                    console.log(`[DB] Inserted ${bulkOperations.length} records. Total inserted: ${successfulInserts}`);
                    bulkOperations = []; // Clear the array safely by reassigning
                }

            } catch (err) {
                console.error(`[ERROR] Failed to process file ${filePath}:`, err.message);
                failedInserts++;
            }
        }

        // Execute any remaining bulk operations
        if (bulkOperations.length > 0) {
            await collection.bulkWrite(bulkOperations, { ordered: false });
            successfulInserts += bulkOperations.length;
            console.log(`[DB] Inserted final ${bulkOperations.length} records.`);
        }

        console.log(`\n[COMPLETE] Data insertion finished.`);
        console.log(`Total Files Processed: ${jsonFiles.length}`);
        console.log(`Successful Inserts: ${successfulInserts}`);
        console.log(`Failed Files/Inserts: ${failedInserts}`);
        
        // 5. Create Indexes for efficient querying
        console.log(`[INDEX] Creating indexes for fast searching...`);
        // Index 1: Unique index on the primary CVE-ID for fast lookups
        await collection.createIndex({ 'cveMetadata.cveId': 1 }, { unique: true });
        
        // Index 2: Text index on the aggregated description field for full-text searching
        await collection.createIndex({ search_text: "text" });

        console.log(`[INDEX] Indexes created successfully!`);

    } catch (err) {
        console.error(`\n[CRITICAL ERROR] Failed during import process:`, err);
    } finally {
        if (client) {
            await client.close();
            console.log('[DB] MongoDB connection closed.');
        }
        console.log('[END] Importer script finished.');
    }
}

importData();