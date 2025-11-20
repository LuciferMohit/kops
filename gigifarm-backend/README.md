# Gigifarm Backend created via CMD
Run:
npm install
mysql -u root -p < migrations/create_tables.sql
npm run seed
npm start
