# number-of-days-left-ssl
証明書の有効期限が近づいてきたらAmazon SNSおよびSlackで通知するスクリプトです。

====

## Install
AWS Lambdaでスクリプトをアップロードまたはコピペするだけです。  
ランタイムは Python 3.7 で動作確認しています。

### Lambda環境変数
Lambda環境変数で下記の3つを設定します。

Domain：証明書の有効期限をチェックする対象のドメインです。コンマ(,)区切りで複数指定可能です。  
SNSTopic：メール通知するためのAmazon SNSトピックARNです。  
SlackUrl：Slackに通知するためのWebhook URLです。

### IAMロール
AWSLambdaBasicExecutionRoleポリシーに sns:Publish ポリシーを追加したロールが必要です。
