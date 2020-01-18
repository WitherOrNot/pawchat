function upload() {
	form_data = new FormData();
	file = document.getElementById("file").files[0]
	form_data.append("file", file)

    return fetch("https://file.io/", {
    		method: "POST",
            body: form_data
    }).then(
    		(response) => response.json()
    ).then(
    		(result) => {
                console.log(result.link);
                return {link: result.link, filename: file.name};
        }
    );
}

function post_msg(msg) {
    form_data = new FormData();
    console.log(msg);
    form_data.append("message", msg);
    return fetch("/message", {
        method: "POST",
        body: form_data
    }).then(
        (response) => response.text()
    ).then(
        (result) => {
            console.log(result);
            return result;
        }
    )
}

function send_msg() {
    files = document.getElementById("file").files;
    msg = document.getElementById("message").value;

    if (files.length > 0) {
        upload().then(
            (result) => {
                link_element = document.createElement("a");
                link_element.href = result.link;
                link_element.download = result.filename;
                link_element.target = "_blank";

                if (msg == "") {
                    link_element.innerText = he.encode(result.filename);
                } else {
                    link_element.innerText = he.encode(msg);
                }

                link_element_txt = link_element.outerHTML;
                console.log(link_element_txt);
                return post_msg(link_element_txt);
            }
        )
    } else {
        post_msg(linkifyStr(he.encode(msg)));
    }

    document.getElementById("message").value = "";
    document.getElementById("file").value = "";
    document.getElementById("choose-label").innerText = "Choose file";
    return false;
}

function update_label(elem) {
    document.getElementById("choose-label").innerText = elem.files[0].name;
}

async function poll_messages() {
    let response = await fetch("/newmsg", {
        method: "GET"
    }).then(
        (response) => response.json()
    ).then(
        (result) => {
            if (result.length > 0) {
                console.log(result)
            }

            return result
        }
    )

    for (m of response) {
        msg = document.createElement("li")
        msg.innerHTML = "<strong>"+m.author+"</strong>: "+m.content
        document.getElementById("chatlist").appendChild(msg)
        scrollTo(0,999999999999999999999999999)
    }

    await poll_messages();
}

