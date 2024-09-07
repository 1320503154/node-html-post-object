const dotenv = require("dotenv");
dotenv.config();
console.log(process.env.OSS_ACCESS_KEY_ID);
console.log(process.env.OSS_ACCESS_KEY_SECRET);
console.log(process.env.OSS_STS_ROLE_ARN);

module.exports = {
	// 从环境变量中获取RAM用户的访问密钥和目标RAM角色的Arn.
	accessKeyId: process.env.OSS_ACCESS_KEY_ID,
	accessKeySecret: process.env.OSS_ACCESS_KEY_SECRET,
	roleArn: process.env.OSS_STS_ROLE_ARN,
	// region填写Bucket所在地域。以华东1（杭州）为例，Region填写为oss-cn-hangzhou。
	region: "oss-cn-guangzhou",
	// 指定Bucket名称。
	bucket: "wt-web-backend-david",
};
