# keyhacks
This repository shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid.

## Slack Webhook (Reference- https://api.slack.com/incoming-webhooks)
```
curl -s -X POST -H "Content-type: application/json" -d '{"text":"streaak"}' "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

## SauceLabs Username and access Key (Reference - https://wiki.saucelabs.com/display/DOCS/Account+Methods)
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

## Github Token
```
curl -s -u "hehe:TOKEN_HERE" https://api.github.com/user
curl -s -H "Authorization: token TOKEN_HERE" "https://api.github.com/users/USERNAME_HERE/orgs
```

## Twilio Account_sid and Auth token
```
curl -X GET 'https://api.twilio.com/2010-04-01/Accounts/ACCOUNT_SID/Keys.json' -u ACCOUNT_SID:AUTH_TOKEN
```
