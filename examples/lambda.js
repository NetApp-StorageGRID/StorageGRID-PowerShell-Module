'use strict';
console.log('Loading function');

exports.handler = (event, context, callback) =>
{

    // setup s3 access
    // decode S3 key
    var aws = require('aws-sdk'),
        s3 = new aws.S3({endpoint: "https://s3.amazonaws.com"}),
        safeKey = decodeURIComponent(event.Records[0].s3.object.key.replace(/\+/g, '%20')),
        safeBucket = event.Records[0].s3.bucket.name;

    aws.config.s3ForcePathStyle = true;

    console.log("Received event: " + JSON.stringify(event));


    s3.getObject({Bucket: safeBucket, Key: safeKey}, function (err, data) {
        if (err) {
            console.error("Unable to \"GET\" obj: " + safeKey + " from bucket: " + safeBucket + "\n" + err)
        }
        else {
            console.log("\"Get\" completed, now \"Put\" to target..")

            var params = {
                endpoint: 'https://YOUR-S3-endpoint',
                credentials: new aws.Credentials('YOUR-AWS-ACCESS-ID', 'YOUR-AWS-SECRET-KEY')
            }

            var s3Webscale = new aws.S3(params)
            s3Webscale.putObject({Bucket: 'myBkt1', Key: safeKey, Body: data.Body}, function (err, d) {
                if (err)
                    console.error(err)
                else
                    console.log('Updated target');
            })
        }
    })


    callback(null, {key: safeKey, bucket: safeBucket});  // Echo back what we put
}