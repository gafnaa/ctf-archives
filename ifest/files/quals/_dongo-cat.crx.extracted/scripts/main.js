function main() {
    // make sure jquery is loaded
    if (typeof $ !== "function") {
        console.error("This script needs jQuery");
        return;
    }

    const storageKey = 'showCat'

    const GIF_SOURCE = chrome.runtime.getURL("assets/bongo-cat.gif");
    const IMG_SOURCE = chrome.runtime.getURL("assets/idle.png");

    const $newGif = $('<img>', {
        src: IMG_SOURCE,
        css: {
            position: 'fixed',
            zIndex: 10000,
            bottom: '50px',
            right: '50px',
            width: '100px',
            height: '100px',
            borderRadius: '200px'
        }
    });

    $('body').append($newGif);

    chrome.storage.sync.get([storageKey], function (result) {
        const isChecked = result[storageKey];
        if (isChecked) $newGif.show()
        else if (isChecked === undefined) $newGif.show()
        else $newGif.hide()
    });

    let timeout;

    const keyPressListener = () => {
        clearTimeout(timeout);
        if ($newGif.attr('src') !== GIF_SOURCE) {
            $newGif.attr('src', GIF_SOURCE);
        }

        timeout = setTimeout(() => {
            $newGif.attr('src', IMG_SOURCE);
        }, 500);
    };

    $(document).on('keypress', keyPressListener);

    chrome.storage.onChanged.addListener((changes, namespace) => {
        for (let [key, { newValue }] of Object.entries(changes)) {
            if (key === storageKey) {
                if (newValue) {
                    $newGif.show()
                } else {
                    $newGif.hide()
                }
            }
        }
    });
}

console.log("Initializing...")
main()
console.log("Done initializing...")