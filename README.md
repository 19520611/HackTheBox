> # FORENSICS
> # Challenge Name: [Plug](https://drive.google.com/file/d/18TzLKFKBT45-5Ii961zl5kEAl4mb1qY6/view?usp=sharing)
> # Author: St1rr1ng (Team: UIT.ζp33d_0∫_Ψ1m3)
![screenshoot](https://i.imgur.com/4TPYCsB.png)

### Mình mở tệp pcapng bằng Wireshark và nhanh chóng thấy rằng đó là việc ghi lại một số quá trình truyền dữ liệu USB giữa một máy chủ lưu trữ và những gì có vẻ là một ổ USB flash.
### Các filter được sử dụng trong Wireshark cho traffic này có thể xem [ở đây](https://www.wireshark.org/docs/dfref/u/usb.html)
### Mặt khác, chúng tôi thấy rằng dữ liệu hàng loạt này được chuyển đến ```device address: 6``` trong USB bus, vì vậy mình xây dựng bộ lọc Wireshark sau để chỉ nhận các gói đó:

```
usb.device_address==6 && usb.capdata
```

![screenshoot](https://i.imgur.com/fOEsX4z.png)

### Mình sử dụng [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) để trích xuất các gói tin:

```
kali@kali:~/Desktop/CTF/HTB-Uni/Plug$ tshark -r capture.pcapng -Y 'usb.capdata and usb.device_address==6' -T text
  481   3.759606         host → 1.6.2        USB 539 URB_BULK out
  492   3.762974        1.6.1 → host         USB 45 URB_BULK in
  497   3.763140         host → 1.6.2        USB 4123 URB_BULK out
  503   3.766387         host → 1.6.2        USB 539 URB_BULK out
  509   3.769593         host → 1.6.2        USB 539 URB_BULK out
  515   3.773330         host → 1.6.2        USB 4123 URB_BULK out
  521   3.777081         host → 1.6.2        USB 5147 URB_BULK out
  527   3.780815         host → 1.6.2        USB 4123 URB_BULK out
  533   3.788441         host → 1.6.2        USB 4123 URB_BULK out
  543   3.797897         host → 1.6.2        USB 1051 URB_BULK out
  549   3.801127         host → 1.6.2        USB 539 URB_BULK out
  555   3.804670         host → 1.6.2        USB 539 URB_BULK out
  987   7.692398         host → 1.6.2        USB 539 URB_BULK out
  998   7.695867        1.6.1 → host         USB 45 URB_BULK in
 1003   7.696068         host → 1.6.2        USB 4123 URB_BULK out
 1009   7.699230         host → 1.6.2        USB 4123 URB_BULK out
 1015   7.702294         host → 1.6.2        USB 539 URB_BULK out
 1021   7.705740         host → 1.6.2        USB 539 URB_BULK out
 1027   7.709906         host → 1.6.2        USB 4123 URB_BULK out
 1033   7.713758         host → 1.6.2        USB 4123 URB_BULK out
 1039   7.716869         host → 1.6.2        USB 539 URB_BULK out
 1049   7.724981         host → 1.6.2        USB 1051 URB_BULK out
 1055   7.728213         host → 1.6.2        USB 539 URB_BULK out
 1061   7.731636         host → 1.6.2        USB 539 URB_BULK out
 1539  12.419485         host → 1.6.2        USB 539 URB_BULK out
 1550  12.422887        1.6.1 → host         USB 45 URB_BULK in
 1555  12.423035         host → 1.6.2        USB 4123 URB_BULK out
 1561  12.426195         host → 1.6.2        USB 4123 URB_BULK out
 1567  12.429171         host → 1.6.2        USB 539 URB_BULK out
 1573  12.432601         host → 1.6.2        USB 539 URB_BULK out
 1579  12.436259         host → 1.6.2        USB 4123 URB_BULK out
 1585  12.439676         host → 1.6.2        USB 4123 URB_BULK out
 1591  12.442802         host → 1.6.2        USB 2075 URB_BULK out
 1601  12.450847         host → 1.6.2        USB 1051 URB_BULK out
 1607  12.454081         host → 1.6.2        USB 539 URB_BULK out
 1613  12.457509         host → 1.6.2        USB 539 URB_BULK out
 1781  16.018247         host → 1.6.2        USB 539 URB_BULK out
 1792  16.021756        1.6.1 → host         USB 45 URB_BULK in
 1797  16.021903         host → 1.6.2        USB 4123 URB_BULK out
 1803  16.025035         host → 1.6.2        USB 539 URB_BULK out
 1809  16.028314         host → 1.6.2        USB 539 URB_BULK out
 1815  16.032427         host → 1.6.2        USB 4123 URB_BULK out
 1821  16.035434         host → 1.6.2        USB 539 URB_BULK out
 1827  16.038946         host → 1.6.2        USB 539 URB_BULK out
 1833  16.043731         host → 1.6.2        USB 4123 URB_BULK out
 1839  16.046847         host → 1.6.2        USB 539 URB_BULK out
 1845  16.050379         host → 1.6.2        USB 539 URB_BULK out
 1855  16.060322         host → 1.6.2        USB 1051 URB_BULK out
 1861  16.063627         host → 1.6.2        USB 539 URB_BULK out
 1867  16.067105         host → 1.6.2        USB 539 URB_BULK out
```

### Sau đó mình giải nén các gói tin vào file raw: 

```
# tshark -r fore2.pcap -Y 'usb.capdata and usb.device_address==3' -T fields -e usb.capdata > raw
```

## Trong đó: 
> -r: Đọc dữ liệu gói từ infile.

> -Y: Display filter

> -T: Đặt định dạng của đầu ra khi xem dữ liệu gói được giải mã 

> -e: Thêm một filter vào danh sách các filter để hiển thị nếu các filter -T được chọn.

> usb.capdata: lấy dữ liệu gói từ filter 'USB Leftover'

### Bây giờ mình chuyển đổi hex file sang binary bằng cách sử dụng [xxd](https://www.tutorialspoint.com/unix_commands/xxd.htm)

```
# xxd -r -p raw output.bin
```

## Trong đó:
> -r: revert - reverse operation: đổi hexdump sang binary

> -p: kiểu hexdump đơn giản

### Sau đó mình thử [binwalk](http://manpages.ubuntu.com/manpages/bionic/man1/binwalk.1.html) để tìm những file bị ẩn bên trong.
```
kali@kali:~/Desktop/CTF/HTB-Uni/Plug$ binwalk output.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
63542         0xF836          PNG image, 200 x 200, 8-bit/color RGBA, non-interlaced
63583         0xF85F          Zlib compressed data, default compression

```
### Binwalk tìm thấy một hình ảnh PNG ẩn bên trong binary. . Nếu nó không được giải nén bằng lệnh trước đó, chúng ta có thể sử dụng:

```
kali@kali:~/Desktop/CTF/HTB-Uni/Plug$ binwalk -D 'png image:png' output.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
63542         0xF836          PNG image, 200 x 200, 8-bit/color RGBA, non-interlaced
63583         0xF85F          Zlib compressed data, default compression

```
### Hình ảnh được lưu trữ trong file ```_output.bin.extracted ```

### Mở file ra ta thấy file ảnh QRCode. Scan ta có ngay flag

![screenshoot](https://i.imgur.com/cofj4Py.png)

![screenshoot](https://i.imgur.com/FXi28up.png)

![screenshoot](https://i.imgur.com/JVCoCfX.png)

> # FLAG: HTB{IN73R3S7iNG_Us8_s7UFf}








