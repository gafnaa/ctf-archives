document.addEventListener('DOMContentLoaded', function () {
    const checkbox = document.getElementById('cat-checkbox');
    const storageKey = 'showCat';

    // Load the value from chrome.storage and update checkbox state
    chrome.storage.sync.get([storageKey], function (result) {
        const isChecked = result[storageKey];
        if (typeof isChecked !== 'undefined') {
            checkbox.checked = isChecked;
        } else {
            checkbox.checked = true
            chrome.storage.sync.set({ [storageKey]: true }, function () {
                console.log('Cat toggle saved as:', true);
            });
        }
    });

    // Update chrome.storage when checkbox is toggled
    checkbox.addEventListener('change', function () {
        const newValue = checkbox.checked;
        chrome.storage.sync.set({ [storageKey]: newValue }, function () {
            console.log('Cat toggle saved as:', newValue);
        });
    });
});