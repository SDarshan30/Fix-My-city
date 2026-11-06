// Destructive, one-time demo data seeder. Requires an explicit confirmation.
// Run with DATABASE_URL pointing at the intended PostgreSQL database.
const { Pool } = require('pg');
const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');

const CONFIRMATION = 'REPLACE ALL REPORTS WITH 100 TAMIL NADU DEMO REPORTS';
const COUNT = 100;
const locations = [
  ['Chennai', 'T. Nagar bus terminus'], ['Chennai', 'Velachery MRTS station road'],
  ['Chennai', 'Mylapore Kapaleeswarar Temple vicinity'], ['Chennai', 'Perambur railway station approach'],
  ['Chennai', 'Anna Nagar Roundtana'], ['Chennai', 'Tambaram Sanatorium junction'],
  ['Chennai', 'Adyar bus depot area'], ['Chennai', 'Ambattur OT bus stand'],
  ['Coimbatore', 'Gandhipuram Town Bus Stand'], ['Coimbatore', 'RS Puram DB Road'],
  ['Coimbatore', 'Peelamedu Avinashi Road'], ['Coimbatore', 'Ukkadam bus stand area'],
  ['Madurai', 'Periyar bus stand approach'], ['Madurai', 'Mattuthavani bus stand road'],
  ['Madurai', 'Anna Nagar main road'], ['Madurai', 'Thirupparankundram temple road'],
  ['Tiruchirappalli', 'Srirangam railway station road'], ['Tiruchirappalli', 'Central Bus Stand area'],
  ['Tiruchirappalli', 'Thillai Nagar 5th Cross'], ['Salem', 'New Bus Stand approach road'],
  ['Salem', 'Hasthampatti junction'], ['Tiruppur', 'Old Bus Stand area'],
  ['Erode', 'Railway Station Road'], ['Vellore', 'Katpadi railway station approach'],
  ['Thanjavur', 'Old Bus Stand area'], ['Tirunelveli', 'Palayamkottai bus stand road'],
  ['Thoothukudi', 'VOC Market approach'], ['Dindigul', 'Main Bus Stand road'],
  ['Nagercoil', 'Vadasery bus stand area'], ['Cuddalore', 'Manjakuppam market road'],
  ['Hosur', 'Bagalur Road junction'], ['Kanchipuram', 'Kamakshi Amman Temple vicinity'],
  ['Karur', 'Bus Stand approach road'], ['Krishnagiri', 'New Bus Stand road'],
  ['Ramanathapuram', 'Market Road'], ['Sivakasi', 'Bus Stand approach'],
  ['Virudhunagar', 'Railway station road'], ['Namakkal', 'Bus Stand area'],
  ['Nagapattinam', 'New Bus Stand approach'], ['Tiruvannamalai', 'Girivalam road vicinity']
];
const issueTypes = [
  { category: 'Road Damage', severity: 'High', text: 'DEMO SAMPLE — A pothole is making the road difficult for two-wheelers. சாலையில் பள்ளம் இருப்பதால் இருசக்கர வாகனங்களுக்கு சிரமமாக உள்ளது.' },
  { category: 'Garbage', severity: 'Medium', text: 'DEMO SAMPLE — Waste has remained near the roadside collection point. சாலையோர குப்பை சேகரிப்பு இடத்தில் குப்பை தேங்கியுள்ளது.' },
  { category: 'Drainage', severity: 'High', text: 'DEMO SAMPLE — A blocked drain is causing water to collect after rain. மழைக்குப் பிறகு வடிகாலில் அடைப்பு ஏற்பட்டு தண்ணீர் தேங்குகிறது.' },
  { category: 'Water Leakage', severity: 'Medium', text: 'DEMO SAMPLE — Water is leaking from a public pipe near the footpath. நடைபாதை அருகிலுள்ள பொதுக் குழாயில் தண்ணீர் கசிகிறது.' },
  { category: 'Streetlight', severity: 'Medium', text: 'DEMO SAMPLE — The streetlight is not working after sunset. மாலை நேரத்தில் தெருவிளக்கு எரியவில்லை.' },
  { category: 'Other', severity: 'Low', text: 'DEMO SAMPLE — A damaged public sign needs attention. சேதமடைந்த பொதுவழி அறிவிப்புப் பலகையை சரிசெய்ய வேண்டும்.' }
];
const workerByCategory = {
  'Road Damage': 'Arun', Garbage: 'Kumar', Drainage: 'Ravi',
  'Water Leakage': 'Meena', Streetlight: 'Suresh', Other: 'Kumar'
};

function isoDaysAgo(days, hours = 0) {
  return new Date(Date.now() - days * 86400000 - hours * 3600000).toISOString();
}

async function main() {
  if (!process.env.DATABASE_URL) throw new Error('Set DATABASE_URL to the PostgreSQL database you intend to replace.');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
  const rl = readline.createInterface({ input: stdin, output: stdout });
  try {
    const target = await pool.query('SELECT current_database() AS db, inet_server_addr()::text AS host');
    const db = target.rows[0];
    console.log(`TARGET DATABASE: ${db.db} at ${db.host || 'local server'}`);
    const existing = await pool.query('SELECT COUNT(*)::int AS count FROM civic_reports');
    console.log(`This will permanently replace ${existing.rows[0].count} existing reports with ${COUNT} fictional Tamil Nadu demo reports.`);
    console.log('Demo reports use FC-DEMO IDs and contain no real reporter contact details.');
    const answer = await rl.question(`Type exactly to continue: ${CONFIRMATION}\n> `);
    if (answer !== CONFIRMATION) {
      console.log('Confirmation did not match. No reports were changed.');
      return;
    }

    const reports = Array.from({ length: COUNT }, (_, n) => {
      const index = n + 1;
      const place = locations[(index * 17) % locations.length];
      const issue = issueTypes[(index * 5 + Math.floor(index / locations.length)) % issueTypes.length];
      const status = index <= 20 ? 'Pending' : index <= 40 ? 'Assigned' : 'Resolved';
      const ageDays = 3 + ((index * 7) % 52);
      const createdAt = isoDaysAgo(ageDays, (index * 3) % 24);
      const worker = status === 'Pending' ? '' : workerByCategory[issue.category];
      const assignedAt = status === 'Pending' ? '' : new Date(new Date(createdAt).getTime() + 6 * 3600000).toISOString();
      const resolvedAt = status === 'Resolved'
        ? new Date(Math.min(Date.now() - 3600000, new Date(createdAt).getTime() + (1 + index % 8) * 86400000)).toISOString()
        : '';
      return {
        id: `FC-DEMO-${String(index).padStart(3, '0')}`,
        reporter: '', contact: '',
        description: issue.text,
        location: `${place[1]}, ${place[0]}, Tamil Nadu`,
        category: issue.category,
        severity: index % 9 === 0 ? 'Low' : issue.severity,
        gps: '', beforePhoto: '', afterPhoto: '', status, worker,
        createdAt, assignedAt, resolvedAt
      };
    });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('DELETE FROM civic_reports');
      for (const report of reports) {
        await client.query(
          'INSERT INTO civic_reports (id, report, created_at) VALUES ($1, $2::jsonb, $3)',
          [report.id, JSON.stringify(report), report.createdAt]
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    console.log('Done: 100 Tamil Nadu demo reports created (20 pending/unassigned, 20 assigned, 60 resolved).');
  } finally {
    rl.close();
    await pool.end();
  }
}

main().catch(error => { console.error(`Could not seed demo reports: ${error.message}`); process.exitCode = 1; });
