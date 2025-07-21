document.querySelectorAll('.response-ui').forEach((e)=>{
    e.textContent = JSON.stringify(JSON.parse(e.dataset.response), null , 2)
    hljs.highlightBlock(e);
})

document.querySelectorAll('.btn-endpoint').forEach((btns)=>{
    btns.addEventListener('click', (btn)=>{
        const parentDiv = btns.closest('[data-tab]');
        parentDiv.querySelectorAll('.btn-endpoint').forEach((btn) => {
            btn.disabled = true
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1 animate-spin" viewBox="0 0 24 24" stroke-width="1.25" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M12 3a9 9 0 1 0 9 9"></path></svg>Test Endpoint';
        })

        const url = parentDiv.querySelector('input[name="url"]').value
        const data = parentDiv.querySelector('input[name="data-body"]').value
        const method = parentDiv.querySelector('input[name="method"]').value
        let rui = parentDiv.querySelector('.response-ui')
        const rscode= parentDiv.querySelector('.response-status-code')
        axios({
            method,
            url,
            data : JSON.parse(data),
            responseType : 'arraybuffer',
        }).then((res)=>{
            setTimeout(() => {
                parentDiv.querySelectorAll('.btn-endpoint').forEach((btn) => {
                    btn.disabled = false
                    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M21 7l-18 0"></path><path d="M18 10l3 -3l-3 -3"></path><path d="M6 20l-3 -3l3 -3"></path><path d="M3 17l18 0"></path></svg>Test Endpoint'
                })
            }, 1000);
            const arrayBuffer = res.data;
            if(res.headers['content-type'].includes('application/json')){
                var json = new TextDecoder('utf-8').decode(new Uint8Array(arrayBuffer));
                rui.textContent = JSON.stringify(JSON.parse(json) ?? {}, null , 2)
                rscode.setHTML('<span class="text-green-600">'+res.status+'</span>')
                hljs.highlightBlock(rui);
            } else if(res.headers['content-type'].includes('image/')){
                const base64Data = btoa(new Uint8Array(arrayBuffer).reduce((data, byte) => {
                    return data + String.fromCharCode(byte);
                }, ''));

                const newTab = window.open();
                if(!newTab){
                    playN()
                    return toast.toast({
                        style: 'bug',
                        title: 'Pop-ups Blocked',
                        msg: 'Izinkan Browser ini membuka tab baru.',
                    })
                }
                newTab.document.write(`<html style="height: 100%;"><head><meta name="viewport" content="width=device-width, minimum-scale=0.1"><title>Response API</title></head><body style="margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: rgb(14, 14, 14);"><img style="display: block;-webkit-user-select: none;margin: auto;background-color: hsl(0, 0%, 90%);transition: background-color 300ms; max-width: 100%; max-height: 100%" src="data:${res.headers['content-type']};base64,${base64Data}"></body></html>`);
            }
        }).catch((err)=>{
            setTimeout(() => {
                parentDiv.querySelectorAll('.btn-endpoint').forEach((btn) => {
                    btn.disabled = false
                    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 mr-1" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor" fill="none" stroke-linecap="round" stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"></path><path d="M21 7l-18 0"></path><path d="M18 10l3 -3l-3 -3"></path><path d="M6 20l-3 -3l3 -3"></path><path d="M3 17l18 0"></path></svg>Test Endpoint'
                })
            }, 1000);
            // console.error(err);
            rui.textContent = JSON.stringify(JSON.parse(new TextDecoder('utf-8').decode(new Uint8Array(err?.response?.data))) ?? {}, null , 2)
            rscode.setHTML('<span class="text-red-600">'+err?.response?.status ?? 500 +'</span>')
            hljs.highlightBlock(rui);
        })
    })
})
