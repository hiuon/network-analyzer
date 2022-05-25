google.charts.load('current', {'packages':['corechart', 'line', 'controls'], callback: this.drawChart});
google.charts.setOnLoadCallback(drawChart);
function drawChart() {
    var data = new google.visualization.DataTable();
    data.addColumn('string', 'Time');
    data.addColumn('number', 'High border');
    data.addColumn('number', 'Low border');
    data.addColumn('number', 'Real');
    data.addColumn('number', 'RealRS');
    data.addRows([
        ['13:20:00\n 22/04/2022',  0.88, 0.65, 0.743252353532, 0.753252353532],
        ['13:20:06\n 22/04/2022',  0.88, 0.65, 0.7232532523542, 0.753252353532],
        ['13:20:12\n 22/04/2022',  0.88, 0.65, 0.7523542513123, 0.753252353532],
        ['13:20:18\n 22/04/2022',  0.88, 0.65, 0.635325324141, 0.753252353532],
        ['13:20:24\n 22/04/2022',  0.88, 0.65, 0.7325324314134, 0.753252353532],
        ['13:20:30\n 22/04/2022',  0.88, 0.65, 0.79523542423, 0.753252353532],
        ['13:20:36\n 22/04/2022',  0.88, 0.65, 0.732532534141, 0.753252353532],
        ['13:20:42\n 22/04/2022',  0.88, 0.65, 0.72325325241, 0.753252353532],
        ['13:20:48\n 22/04/2022',  0.88, 0.65, 0.7531531656, 0.753252353532],
        ['13:20:54\n 22/04/2022',  0.88, 0.65, 0.63356475853, 0.753252353532],
        ['13:21:00\n 22/04/2022',  0.88, 0.65, 0.74378649876, 0.753252353532],
        ['13:21:06\n 22/04/2022',  0.88, 0.65, 0.796578647634, 0.753252353532]
    ]);
    var options = {
        'width': 1100,
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
    var chart = new google.visualization.LineChart(document.getElementById('chartBlock'));
    var intervals = document.getElementsByName("interval");
    var defaultInterval = "30";


    drawUpdatedChart({target: defaultInterval});
    function drawUpdatedChart(sender) {

        chart.draw(data, options);
    }
}