
<p align="center">
  <img src="img/OuiKeyLeaks.png" alt="Description de l'image" width="300"/>
</p>


# Scenario

*OuiKeyLeaks have been seized for publishing a bad article about drones! 
Out of curiosity, can you help us pentesting this website ? Try retrieving the admin's password hash.  
Spoiler : It's going to take some escalation !  
Have fun.*
# Step 1

The challenge gave me a domain and port to connect to the challenge.
After connecting to the website I see  this page:

![[S1-1.png]]

If I am a part of investigator team, I would connect to the website.
I look at the source code and see this:

![[S1-2.png]]

This script check if there is a cookie named "magic_cookie" set.
Then it checks if the cookie value is `investigator`.
If yes, there is a redirection to `/OuiKL/blog.html`

I set the expected cookie.

![[S1-3.png]]

I update the page, and the message has changed:

![[S1-4.png]]

# Step 2


On the next page, I see that I need another cookie session to go to the admin page.

![[S2-1.png]]

There is a chat service at the bottom right corner.

![[S2-2.png]]

I can't even see the messages because of this fucking publicity!
I see that at the bottom left corner :

![[S2-3.png]]

I have a `premium` cookie set to `false`.
I set it to `true` and get disbarassed of this publicities spam.

![[S2-4.png]]

In the chat, there are other investigator which send messages.
I test to trigger an XSS with this simple payload:
`<img src=1 onerror='alert(1)'>`

![[S2-5.png]]

The XSS worked!
Now I try to recover an elevated cookie with this payload as this is a Websocket:
`<img src=x onerror=socket.send(document.cookie)>`

The cookie will be sent to everybody in this chat.
I wait a little and get the special cookie!

![[S2-6.png]]

`guid:51af8760-3cbf-4344-bcba-7f142d3157e7`
I set the cookie and connect to the admin page.
# Step 3

I am connected to the admin panel:

![[S3-1.png]]

In the "View Logs" menu, I see this interesting log :

![](img/S3-2)

There is an `/admin/notes.txt` endpoint.
In these notes, I see this interesting source code of `user.php`:

```php
<?php
header("Content-Type: application/json");
require_once '../config/config.php'; // Connexion PDO

// Check if guid is present
if (isset($_COOKIE['guid'])) {
    $guid = $_COOKIE['guid'];

    $query = "SELECT name, secret FROM users WHERE guid = '$guid'"; 
    $result = $pdo->query($query);
    $userData = $result->fetch(PDO::FETCH_ASSOC);

    if ($userData) {
        echo json_encode([
            "success" => true,
            "name" => $userData['name'],
            "secret" => $userData['secret']
        ]);
    } else {
        echo json_encode(["success" => false, "message" => "Unknown GUID"]);
    }
} else {
    echo json_encode(["success" => false, "message" => "No guid found..."]);
}
?>
```

The guid cookie value is directly injecteeed in an SQL query without any sanitization.
I open burp and use the repeater to test it.
By adding a `'` to the guid value, I trigger a server Internal Error, this confirm the SQLi. 

![[S3-3.png]]

I check the datasse version.

![[S3-4.png]]

Then use GROUP_CONCAT to have the databases name.

![[S3-5.png]]

Tables:

![[S3-6.png]]

Columns:

![[S3-7.png]]

And finally, I dump the flag:

![[S3-8.png]]

`ECW{M4stery_Of_All_T3chniques_gg}`

