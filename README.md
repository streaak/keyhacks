# KeyHacks
This repository shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid.

## [Slack Webhook](https://api.slack.com/incoming-webhooks)
```
curl -s -X POST -H "Content-type: application/json" -d '{"text":"streaak"}' "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

## [SauceLabs Username and access Key](https://wiki.saucelabs.com/display/DOCS/Account+Methods)
```
curl -u USERNAME:ACCESS_KEY https://saucelabs.com/rest/v1/users/USERNAME
```

## Facebook AppSecret
```
You can generate access tokens by visiting the below URL-
https://graph.facebook.com/oauth/access_token?client_id=ID_HERE&client_secret=SECRET_HERE&redirect_uri=&grant_type=client_credentials
```

## Facebook Access Token  
```
https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2
```

## [Github Token](https://developer.github.com/v3/)
```
curl -s -u "hehe:TOKEN_HERE" https://api.github.com/user
curl -s -H "Authorization: token TOKEN_HERE" "https://api.github.com/users/USERNAME_HERE/orgs
```

## Twilio Account_sid and Auth token
```
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Keys.json' -u ACCOUNT_SID:AUTH_TOKEN
```

## [Twitter API Secret](https://developer.twitter.com/en/docs/basics/authentication/guides/bearer-tokens.html)
```
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'
```

## [Twitter Bearer token](https://developer.twitter.com/en/docs/accounts-and-users/subscribe-account-activity/api-reference/aaa-premium)
```
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'
```

## [Deviant Art Secret](https://www.deviantart.com/developers/authentication)
```
curl https://www.deviantart.com/oauth2/token -d grant_type=client_credentials -d client_id=ID_HERE -d client_secret=mysecret
```

## [Deviant Art Access Token](https://www.deviantart.com/developers/authentication)
```
curl https://www.deviantart.com/api/v1/oauth2/placebo -d access_token=Alph4num3r1ct0k3nv4lu3
```

## [Pendo Integration Key](https://help.pendo.io/resources/support-library/api/index.html?bash#authentication)
```
curl -X GET https://app.pendo.io/api/v1/feature -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'
curl -X GET https://app.pendo.io/api/v1/metadata/schema/account -H 'content-type: application/json' -H 'x-pendo-integration-key:KEY_HERE'
```

## [SendGrid API Token](https://sendgrid.com/docs/API_Reference/api_v3.html)
```
curl -X "GET" "https://api.sendgrid.com/v3/scopes" -H "Authorization: Bearer SENDGRID_TOKEN-HERE" -H "Content-Type: application/json"
```

## Dropbox API
```
curl -X POST https://api.dropboxapi.com/2/users/get_current_account --header "Authorization: Bearer "
```

## aws_access_key_id and secret
```
Add the new access_key_id and secret within ~/.aws/credentials file as a new user (https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html)
$ aws s3 ls --profile username_picked
$ aws s3 cp test.txt s3://bucket_belonging_to_the_company --profile username_picked
```
