function startSniffer() {
    var select = document.getElementById("mySelect")
    var value = select.options[select.selectedIndex].value
    console.log(value)
    var _data = fetchAsync("http://localhost:5000/start?deviceName=" + value).then(

    )

}

function stopSniffer() {
    fetchAsync("http://localhost:5000/stop")
}

function updateTestFile() {
    var value = document.getElementById("testD").value
    var select = document.getElementById("mySelectTest")
    var value1 = select.options[select.selectedIndex].value
    fetchAsync("http://localhost:5000/get-test-data?duration="+value+"&deviceName="+value1)
}

function updateData() {
    var interval
    var typeH
    var rad1 = document.getElementsByName("interval")
    for (var i = 0; i < rad1.length; i++) {
        if (rad1[i].checked) interval = rad1[i].value
    }
    var rad2 = document.getElementsByName("type")
    for (var i = 0; i < rad2.length; i++) {
        if (rad2[i].checked) typeH = rad2[i].value
    }
    console.log(typeH + interval)
    var parametersH = []
    var _data = fetchAsync("http://localhost:5000/get-data?type=" + typeH + "&interval=" + interval)
    _data.then(result => {
        result.forEach(info => parametersH.push(info))
        console.log(parametersH)
        var chart = new google.visualization.LineChart(document.getElementById('chartBlock'));
        var options = {
            'width': 1200,
            'height': 500,
            'title' : 'Network Monitoring',
            hAxis: {
                title: 'Time'
            },
            vAxis: {
                title: 'Hurst Parameter'
            },
            series: {
                0: { lineDashStyle: [2, 2] },
                1: { lineDashStyle: [2, 2] }
            },
            pointsVisible: true
        }
        var data = new google.visualization.DataTable();
        console.log(parametersH[0])
        data.addColumn('string', 'Time');
        data.addColumn('number', 'High border');
        data.addColumn('number', 'Low border');
        data.addColumn('number', 'Real');
        for (var i = 0; i < parametersH.length; i++) {
            data.addRows([[parametersH[i].Timestamp, parametersH[i].HighBorder, parametersH[i].LowBorder, parametersH[i].H]])
        }

        chart.draw(data, options);
    })

}