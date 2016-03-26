# Play 2 with box.com upload

This is an example showing Play WS running with the box.com content API in both Java and Scala.

For more information, see https://box-content.readme.io/docs/oauth-20 and https://box-content.readme.io/#oauth-2

To make this project work, you need to create a "/conf/box-credentials.conf" file and add the following:

```
# from https://box-content.readme.io/docs/oauth-20#section-initial-setup
client.id="<client id>"
client.secret="<client secret>"
client.login="your email address"
````

This project is configured for Play 2.4.x, but will work the same (with minor API differences) in 2.5.x.

