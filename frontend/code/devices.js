async function fetchAsync (url) {
    let response = await fetch(url);
    let data = await response.json();
    return data;
}
var _data = fetchAsync("http://localhost:5000/devices");
let devices = []
_data.then(result => {
    result.forEach(device => devices.push(device))
    var selectList = document.getElementById("mySelect");
    var selectListTest = document.getElementById("mySelectTest");
    for (var i = 0; i < devices.length; i++) {
        var option = document.createElement("option");
        var option1 = document.createElement("option");

        option.setAttribute("value", devices.Name);
        option.text = devices[i].Name +" : " + devices[i].IPv4;
        option.value = devices[i].IPv4
        option1.setAttribute("value", devices.Name);
        option1.text = devices[i].Name +" : " + devices[i].IPv4;
        option1.value = devices[i].IPv4
        selectList.appendChild(option);
        selectListTest.appendChild(option1);
    }
});

