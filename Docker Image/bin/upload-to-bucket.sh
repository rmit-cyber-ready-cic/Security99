export AWS_ACCESS_KEY_ID=<AWS_ACCESS_KEY_ID>
export AWS_SECRET_ACCESS_KEY=<AWS_SECRET_ACCESS_KEY>
export AWS_DEFAULT_REGION=<AWS_DEFAULT_REGION>

aws s3 cp report.pdf <s3-bucket-link>
aws s3api put-object-acl --bucket codesecure-config --key report.pdf --acl public-read