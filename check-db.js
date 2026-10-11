const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "nexora.db"), {
  readonly: true
});

try {
  const tables = db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
  ).all();

  console.log("========================================");
  console.log("       NEXORA DATABASE INSPECTION       ");
  console.log("========================================");

  for (const table of tables) {
    console.log(`\nTable: [${table.name}]`);

    const columns = db.prepare(
      "PRAGMA table_info(" + JSON.stringify(table.name) + ")"
    ).all();

    console.table(
      columns.map(col => ({
        cid: col.cid,
        name: col.name,
        type: col.type,
        notnull: Boolean(col.notnull),
        pk: Boolean(col.pk)
      }))
    );

    const count = db.prepare(
      "SELECT COUNT(*) AS total FROM " + JSON.stringify(table.name)
    ).get();

    console.log(`Total records in ${table.name}: ${count.total}`);
  }

  console.log("\n========================================");
} catch (error) {
  console.error("Database inspection failed:", error.message);
} finally {
  db.close();
}
