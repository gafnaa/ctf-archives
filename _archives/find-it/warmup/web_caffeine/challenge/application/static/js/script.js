const show_message = (message, type) => {
    let card = $('#resp-msg');
    card.text(message);
    card.attr('class', `alert alert-${type}`);
    card.show();

    setTimeout(() => {
        card.hide();
    }, 5000)
}

const login = () => {
    let username = $('#username').val();
    let password = $('#password').val();

    if ($.trim(username) === '' || $.trim(password) === '') {
        show_message('All fields required!', 'danger');
        return;
    }

    fetch('/service/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'username': username,
            'password': password
        })
    })
        .then((res) => {
            if (res.status === 200) window.location.replace('/home');
            else show_message('Invalid username/password!', 'danger');
        });
}

const register = () => {
    let username = $('#username').val();
    let password = $('#password').val();

    if ($.trim(username) === '' || $.trim(password) === '') {
        show_message('All fields required!', 'danger');
        return;
    }

    fetch('/service/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'username': username,
            'password': password
        })
    })
        .then((res) => {
            res.json()
                .then((data) => {
                    if (data.message === 'User already exists!') {
                        show_message(data.message, 'danger');
                    }
                    else {
                        show_message(data.message, 'success');
                    }
                })
        });
}

const addProduct = () => {
    let name = $('#product-name').val();
    let price = $('#product-price').val();
    let description = $('#product-description').val();
    let manualUrl = $('#product-manual').val();

    if ($.trim(name) === '' || $.trim(price) === '' || $.trim(description) === '' || $.trim(manualUrl) === '') {
        show_message('All fields required!', 'danger');
        return;
    }

    fetch('/service/product', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            'name': name,
            'price': price,
            'description': description,
            'manual': manualUrl
        })
    })
        .then((data) => data.json())
        .then((res) => {
            if (res.message === "Invalid URL!") {
                show_message(res.message, 'danger');
                return;
            }

            if(res.message === "Produk Tersubmit") {
                show_message(res.message, 'success');
                return
            }
        })
}