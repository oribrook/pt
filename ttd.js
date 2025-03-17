let map = new Map();
map.set(1, 'a');
map.set(2, 'b');
map.set(3, 'c');

for (let [key, value] of map) {
    console.log(key, value); // Logs in order of insertion: 1 'a', 2 'b', 3 'c'
}