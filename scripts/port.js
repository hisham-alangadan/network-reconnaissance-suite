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