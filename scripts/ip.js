try{
    const ipInput = document.getElementById('ip-input');

    ipInput.addEventListener("keypress", function(event)
    {
        if(event.key === "Enter")
        {
            event.preventDefault();
            console.log(ipInput.value);

            if (/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ipInput.value)) {  
                window.location.href = ("./port.html");
            }  
            alert("You have entered an invalid IP address!")  
        }
    });
} catch(e) {}

try{
    const startPort = document.getElementById('start-port-input');
    const endPort = document.getElementById('end-port-input');

    startPort.addEventListener("keypress", function(event)
    {
        if(event.key === "Enter")
        {
            acceptPort();
        }
    })

    endPort.addEventListener("keypress", function(event)
    {
        if(event.key === "Enter")
        {
            acceptPort();
        }
    })

    function acceptPort()
    {
        const start = parseInt(startPort.value);
        const end = parseInt(endPort.value);

        console.log("checking...")
        if(isNaN(start) || isNaN(end)){
            console.log("not a number")
        }
        else
        {
            if(start <= 0 || start >= 65500 || end <=  0 || end >= 65500)
            {
                alert("please enter a port bw 0 and 65500");
                console.log(start)
                console.log(end)
            }
            else
            {
                console.log("Port accepted");
                window.location.href = ("./protocol.html")
            }

        }
    }
} catch(e) {}

var protocol = "DEFAULT";

try{
    function handleTcp() {
        window.location.href = ("./flags.html")
    }

    function handleUdp() {
        window.location.href = ("./output.html")
    }

} catch(e) {}
