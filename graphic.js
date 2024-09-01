//get the file name
const qStr = window.location.search;
const urlParams = new URLSearchParams(qStr);
const name = urlParams.get('name');
//console.log('results/' + name);

// aiAnalysis

  // JavaScript code to load and display the text file content

fetch('results/' + name + '_aiStats.txt')
    .then(response => response.text())
    .then(text => {
      // Wrap the text content inside <pre> tags
      document.getElementById('statsText').innerHTML = '<pre>' + text + '</pre>';
    })
    .catch(error => console.error('Error loading the text file:', error));

fetch('results/' + name + '_aiTree.txt')
    .then(response => response.text())
    .then(text => {
      // Wrap the text content inside <pre> tags
      document.getElementById('treeText').innerHTML = '<pre>' + text + '</pre>';
    })
    .catch(error => console.error('Error loading the text file:', error));

fetch('results/' + name + '_suspiciousPackets.txt')
    .then(response => response.text())
    .then(text => {
      document.getElementById('susPackets').innerHTML = '<pre>' + text + '</pre>';
    })
    .catch(error => console.error('Error loading the text file:', error));




//geoChart

var width = 800;
var height = 500;
var radius = 10;
        // SVG variables
var svg = d3.select("#geoMapDiv").append("svg").attr("width", width).attr("height", height);
var g1 = svg.append("g"); // background
var g2 = svg.append("g"); // pie charts
        // Projection variables
var projection = d3.geoMercator().translate([width/2,height/2]).scale(140);

var path = d3.geoPath().projection(projection);
        // Pie chart variables:
var arc = d3.arc().innerRadius(0).outerRadius(radius);
var pie = d3.pie().sort(null).value(function(d) { return d; });
var color = d3.schemeCategory10;

        // Draw geographic features
d3.json("world.json", function(error, world) {
    g1.insert("path", ".land").datum(topojson.feature(world, world.objects.countries)).attr("class", "land").attr("d", path);
    g1.append("path").datum(topojson.mesh(world, world.objects.countries, function(a, b) { return a !== b; })).attr("class", "mesh").attr("d", path);
});
        // Draw pie charts,
d3.csv('results/' + name + '_processedGeo.csv', function(error, water) {
    //if (!data || data.length === 0) {
    if (!water || water.length === 0) {
        d3.select("#geoMapDiv")
            .append("h3")
            .text("No locations available")
            .style("text-align", "center");
        return; // Exit the function early
    }
        //console.log(water);
        var points = g2.selectAll("g")          //get the lat and long of each point
                .data(water)
                .enter()
                .append("g")
                .attr("transform",function(d) {return "translate("+projection([d.lon,d.lat])+")" })
                .attr("class","pies")
        //console.log(points)

        points.append("text")           //make the labels
                .attr("y", -radius - 5)
                .text(function(d) { return d.label })
                .style('text-anchor','middle')
                .style('font-size', '14px');

        var pies = points.selectAll(".pies")            //deals with the data
                .data(function(d) {return pie(d.data.split(['-'])); })
                .enter()
                .append('g')
                .attr('class','arc');

        pies.append("path")             //makes the circles and fills them
        .attr('d',arc)
        .attr("fill", "#cccccc");

});
//malPortChart
d3.csv('results/' + name + '_processedMalPorts.csv', function(error, item) {
    var parText = document.getElementById('malText');
    const malPort = document.getElementById('malPortChart').getContext('2d');

    console.log(item)
    if (item.length === 0){
        color = "green"
        parText.innerHTML = "No Malicious Port Detected"
        item = [{"port": "none","frequency": "1"}]
    } else {
        color = "red"
        parText.innerHTML = "Malicious Port Detected"
    }

    var itemLabels = item.map(function(d) {return d.port});
    var itemFreq = item.map(function(d) {return d.frequency});

    const myPortChart = new Chart(malPort, {
        type: 'pie',
        data: {
            labels: itemLabels,
            datasets: [{
                backgroundColor: color,
                label: 'Malicious Ports Addresses',
                data: itemFreq,
                borderColor: 'black',
            },],
        },
        options: {
           legend: {
               display: false
           }
        }
    });
});



//timeChart
d3.csv('results/' + name + '_timLen.csv', function(error, item) {
    const time = document.getElementById('timeChart').getContext('2d');

    var itemLabels = item.map(function(d) {return d.time});
    var itemFreq = item.map(function(d) {return d.length});

    const myTimeChart = new Chart(time, {
        type: 'line',
        data: {
            labels: itemLabels,
            datasets: [{
                label: 'time vs length',
                pointRadius: 0,
                borderWidth: 0.75,
                data: itemFreq,
                fill: false,
                borderColor: 'black', // Setting line color to white
            }],
        },
        options: {
           legend: {
               display: false
           },
           scales: {
               xAxes: [{
                   ticks: {
                       fontColor: 'white' // Setting x-axis label color to white
                   },
                   gridLines: {
                       color: 'rgba(255, 255, 255, 0.1)' // Setting x-axis grid color to white with opacity
                   }
               }],
               yAxes: [{
                   ticks: {
                       fontColor: 'white' // Setting y-axis label color to white
                   },
                   gridLines: {
                       color: 'rgba(255, 255, 255, 0.1)' // Setting y-axis grid color to white with opacity
                   }
               }]
           }
        }
    });
});


//protocolChart
d3.csv('results/' + name + '_processedProtocol.csv', function(error, item) {
    var colors = ["red", "green", "blue", "purple", "turquoise", "pink"];
    const protocol = document.getElementById('protocolChart').getContext('2d');

    //console.log(item)
    var itemLabels = item.map(function(d) {return d.protocol});
    var itemFreq = item.map(function(d) {return d.frequency});

    const myProtocolChart = new Chart(protocol, {
        type: 'bar',
        data: {
            labels: itemLabels,
            datasets: [{
                backgroundColor: colors,
                label: 'Protocols',
                data: itemFreq,
                borderColor: 'black',
            },],
        },
        options: {
           legend: {
               display: false
           },
           scales: {
               xAxes: [{
                   ticks: {
                       fontColor: 'white' // Setting x-axis label color to white
                   },
                   gridLines: {
                       color: 'rgba(255, 255, 255, 0.1)' // Setting x-axis grid color to white with opacity
                   }
               }],
               yAxes: [{
                   ticks: {
                       fontColor: 'white' // Setting y-axis label color to white
                   },
                   gridLines: {
                       color: 'rgba(255, 255, 255, 0.1)' // Setting y-axis grid color to white with opacity
                   }
               }]
           }
        }
    });
});



//big num
d3.csv('results/' + name + '_rawSrcIP.csv', function(error, item) {
    document.getElementById('bigNum').innerHTML = item.length;
});



//srcIPChart
d3.csv('results/' + name + '_processedSrcIPs.csv', function(error, item) {
    var colors = ["red", "green", "blue", "purple", "turquoise", "pink"];
    const srcIP = document.getElementById('srcIPChart').getContext('2d');

    var itemLabels = item.map(function(d) {return d.ip});
    var itemFreq = item.map(function(d) {return d.frequency});

    const mysrcIPChart = new Chart(srcIP, {
        type: 'doughnut',
        data: {
            labels: itemLabels,
            datasets: [{
                backgroundColor: colors,
                label: 'Frequency of Source IP addresses',
                data: itemFreq,
                borderColor: 'black',
            },],
        },
        options: {
           legend: {
               display: false
           }
        }
    });
});



//destIPChart
d3.csv('results/' + name + '_processedDestIPs.csv', function(error, item) {
    var colors = ["red", "green", "blue", "purple", "turquoise", "pink"];
    const destIP = document.getElementById('destIPChart').getContext('2d');

    var itemLabels = item.map(function(d) {return d.ip});
    var itemFreq = item.map(function(d) {return d.frequency});


    const myDestIPChart = new Chart(destIP, {
        type: 'doughnut',
        data: {
            labels: itemLabels,
            datasets: [{
                backgroundColor: colors,
                label: 'Frequency of Destination IP addresses',
                data: itemFreq,
                borderColor: 'black',
            },],
        },
        options: {
           legend: {
               display: false
           }
        }
    });
});
