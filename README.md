Optimized planet finder for Dark Forest
----------------------------------------

Playing Dark Forest (http://zkga.me)?

Can't wait for your browser to mine and find new planets? Use this optimized parallelized miner on a strong machine to uncover location of attractive planets on the map!

Planets have population sizes based on their types, in the following descending order:

* Hyper Giant
* Super Giant
* Giant
* Sub Giant
* Yellow Star
* White Dwarf
* Red Dwarf
* Brown Dwarf
* Big Asteroid
* Little Asteroid

The map is proceduarlly generated, where a planet's rarity is based on its hash value - much like the difficulty in proof of work.

Modification of https://github.com/arnaucube/mimc-rs.


Running
-------

`cargo run --release run`

Output
------

The program will print out lines of the form:

```
found 3901, 5120, 1199962823801523089162319037690815755569046001441439505693383955722915806, brown dwarf
```

where the first two elements are the x and y coordinates, the third is the hash and the fourth is the planet type.

