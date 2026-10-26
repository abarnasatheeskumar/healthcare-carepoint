const app = require('./app'), PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CarePoint running at http://localhost:${PORT}`));
