const { exec } = require("child_process");
const path = require("path");
const express = require("express");
const cors = require("cors");

const moment = require("moment");

const OSS = require("ali-oss");
const { STS } = require("ali-oss");

const config = require("./config");

const getToken = async () => {
  const { accessKeyId, accessKeySecret, roleArn, bucket } = config;
  const seconds = 3000; //3000秒，50分钟过期
  const date = new Date();
  date.setSeconds(date.getSeconds() + seconds);
  const dir = "user-dirs/";
  const policy = {
    expiration: date.toISOString(), // 请求有效期。
    conditions: [
      ["content-length-range", 0, 1048576000], // 设置上传文件的大小限制。
      ["starts-with", "$key", dir], // 限制文件只能上传到user-dirs目录下。
      { bucket }, // 限制文件只能上传至指定Bucket。
    ],
  };
  /* 使用stsToken上传。 */
  let stsToken;
  if (roleArn) {
    let sts = new STS({
      accessKeyId,
      accessKeySecret,
    });
    const {
      credentials: { AccessKeyId, AccessKeySecret, SecurityToken },
    } = await sts.assumeRole(roleArn, "", seconds, "sessiontest");
    stsToken = SecurityToken;
    client = new OSS({
      accessKeyId: AccessKeyId,
      accessKeySecret: AccessKeySecret,
      stsToken,
    });
  }

  // 计算签名。
  const formData = await client.calculatePostSignature(policy);

  // 返回参数。
  const params = {
    expire: moment(date).unix().toString(),
    policy: formData.policy,
    signature: formData.Signature,
    accessid: formData.OSSAccessKeyId,
    stsToken,
    host: `http://${config.bucket}.${config.region}.aliyuncs.com`,
    dir,
  };

  return params;
};

const app = express();
app.use(cors());

app.get("/token", async (req, res) => {
  const result = await getToken();
  res.header["Access-Control-Allow-Origin"] = "*";
  res.json(result);
});

app.get(/^(.+)*\.(html|js|ico)$/i, async (req, res) => {
  const pat = path.join(__dirname, "../", req.originalUrl);
  res.sendFile(pat);
});

const url = "http://127.0.0.1:3001/index.html";
app.listen(3001, () => console.log("请打开：" + url));

if (process.platform === "win32") {
  exec(`start ${url}`); // For Windows
} else if (process.platform === "darwin") {
  exec(`open ${url}`); // For macOS
} else {
  exec(`xdg-open ${url}`); // For Linux
}
