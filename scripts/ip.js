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