const express = require("express");
const router = require("./routes");
const cors = require('cors')

const app = express();
app.use(cors())
app.use(express.json())
app.use('/api/v1', router)
//defined port for localhost
const PORT=3002;
app.listen(PORT, () => { console.log("Connected!!!") })
