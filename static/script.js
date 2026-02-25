let startTime = Date.now();

document.querySelector("form").addEventListener("submit", function(){
    let endTime = Date.now();
    let timeTaken = (endTime - startTime)/1000;
    document.getElementById("load_time").value = timeTaken;
});
