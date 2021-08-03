// server.js
const express = require('express');
const fs = require('fs')
const {spawn} = require('child_process')
const fileUpload = require('express-fileupload');

const app = express();
const port = 4000;

// enable files upload
app.use(fileUpload({
    createParentPath: true
}));





app.listen(port, () => {
  console.log(`Success! Your application is running on port ${port}.`);
});

const readAnalyzedData = (()=>{
    const file = fs.readFileSync('/Hackathon/DS_Microsoft_Hackaton/JS_classifier.json', 'utf8');
    console.log(file)
    const f = JSON.parse(file)
    return f
})

app.post("/runAnalyze", function (req, res) {
   
    var dataToSend;
    analyzedFilePath = '/uploadedFiles/' + res.body.filename

    // spawn new child process to call the python script
    const python = spawn('python', ['/Hackathon/DS_Microsoft_Hackaton/file_predictor.py', analyzedFilePath]);
    // collect data from script
    python.stdout.on('data', function (data) {
    console.log('Pipe data from python script ...');
    dataToSend = data.toString();
    });
    // in close event we are sure that stream from child process is closed
    python.on('close', (code) => {
    console.log(`child process close all stdio with code ${code}`);
    console.log('read data from file...')
    
    const fileResult = readAnalyzedData() // Getting json data from file
    // send data to browser
    res.send(fileResult)
    });    
    
});


app.post('/uploadFile', async (req, res) => {
    try {
        if(!req.files) {
            res.send({
                status: false,
                message: 'No file uploaded'
            });
        } else {
            //Use the name of the input field (i.e. "avatar") to retrieve the uploaded file
            let avatar = req.files[''];
            
            //Use the mv() method to place the file in upload directory (i.e. "uploads")
            avatar.mv('./uploadedFiles/' + avatar.name);

            //send response
            res.send({
                status: true,
                message: 'File is uploaded',
                data: {
                    name: avatar.name,
                    mimetype: avatar.mimetype,
                    size: avatar.size,
                    md5: avatar.md5
                }
            });
        }
    } catch (err) {
        res.status(500).send(err);
    }
});