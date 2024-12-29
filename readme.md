### Compiled in 

Device name	abs0-desktop
Processor	12th Gen Intel(R) Core(TM) i5-12400F   2.50 GHz
Installed RAM	16,0 GB (15,8 GB usable)
Device ID	520B9188-B283-4274-8EF3-20095A8C49C8
Product ID	00330-80000-00000-AA783
System type	64-bit operating system, x64-based processor
Pen and touch	No pen or touch input is available for this display

by MinGW


## Input

`
gcc .\check_time.c -o check_time ; ./check_time.exe
`

## Output
Encryption of 64 MB took 44.21 seconds


##### *Cpu Info*
Included in `cpu.info` file.


---

## Input

`
gcc .\enc_name.c -o enc_name ; ./enc_name.exe
`
## Output
Plaintext (hex): 43656D616C20417264612054656B6B6573696E
Plaintext length: 19 bytes

=== Encrypting Block 1 ===
Round  RoundOutput         RoundKey
------------------------------------
 1  d97c5dd04bc8d5ec  0b02679b49a5
 2  92b5f4e5d97c5dd0  69a659256a26
 3  5da4bcd992b5f4e5  45d48ab428d2
 4  9b63770c5da4bcd9  7289d2a58257
 5  d2dbdd3d9b63770c  3ce80317a6c2
 6  d0bff249d2dbdd3d  23251e3c8545
 7  52311b4ed0bff249  6c04950ae4c6
 8  dc2b8b9852311b4e  5788386ce581
 9  409e2ff8dc2b8b98  c0c9e926b839
10  5949f988409e2ff8  91e307631d72
11  ca078cd65949f988  211f830d893a
12  9d3e33d6ca078cd6  7130e5455c54
13  32df7a7b9d3e33d6  91c4d04980fc
14  abb75de432df7a7b  5443b681dc8d
15  d4e71040abb75de4  b691050a16b5
16  d02f984fd4e71040  ca3d03b87032

=== Encrypting Block 2 ===
Round  RoundOutput         RoundKey
------------------------------------
 1  b7468d5fd4081646  0b02679b49a5
 2  f525141eb7468d5f  69a659256a26
 3  0d0f946df525141e  45d48ab428d2
 4  d40ebb320d0f946d  7289d2a58257
 5  ebe14805d40ebb32  3ce80317a6c2
 6  a736a0b8ebe14805  23251e3c8545
 7  5ac55c93a736a0b8  6c04950ae4c6
 8  02198c105ac55c93  5788386ce581
 9  0a70ce4902198c10  c0c9e926b839
10  513766bb0a70ce49  91e307631d72
11  f566f717513766bb  211f830d893a
12  77367addf566f717  7130e5455c54
13  e6df547977367add  91c4d04980fc
14  383f9e4de6df5479  5443b681dc8d
15  a83afacf383f9e4d  b691050a16b5
16  747a0b99a83afacf  ca3d03b87032

=== Encrypting Block 3 ===
Round  RoundOutput         RoundKey
------------------------------------
 1  8021ff5ea8da9a6f  0b02679b49a5
 2  847d09098021ff5e  69a659256a26
 3  27e02099847d0909  45d48ab428d2
 4  883f4eae27e02099  7289d2a58257
 5  55bea212883f4eae  3ce80317a6c2
 6  694ddff355bea212  23251e3c8545
 7  10dd6ce9694ddff3  6c04950ae4c6
 8  9fe8458a10dd6ce9  5788386ce581
 9  494ad8189fe8458a  c0c9e926b839
10  ea8b0409494ad818  91e307631d72
11  4e13da3fea8b0409  211f830d893a
12  078617724e13da3f  7130e5455c54
13  5fb3451a07861772  91c4d04980fc
14  b3b1d9e95fb3451a  5443b681dc8d
15  4ab3ed81b3b1d9e9  b691050a16b5
16  73b07db64ab3ed81  ca3d03b87032

Final Ciphertext (hex): E4E330CC15B131318B5AF879BF423E073BCC7D758C0DE16E
Decrypted (hex): 43656D616C20417264612054656B6B6573696E






# End
From Cemal Arda Tekkesin. 
also available at [Github](https://github.com/catekkesin/507homework2)