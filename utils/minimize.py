import subprocess, sys

image_buf = open(sys.argv[1], 'rb').read()
fuzz_buf = open(sys.argv[2], 'rb').read()
out_buf = ''
final_buf = ''
out_image = 'out.img'
indexes = []

def flush():
  f = open(out_image, 'wb')
  f.write(out_buf)
  f.close()

def test():
  try:
    p = subprocess.check_call(['./ext4-fsfuzz', '-t', 'ext4', '-i', out_image])
  except subprocess.CalledProcessError as e:
    if e.returncode == -6 or e.returncode == -11:
      return True
    else:
      return False

for i in xrange(len(image_buf)):
  if image_buf[i] != fuzz_buf[i]:
    out_buf = final_buf + image_buf[i] + fuzz_buf[i+1:]
    flush()
    if test():
      print i
      final_buf += image_buf[i]
    else:
      final_buf += fuzz_buf[i]
  else:
    final_buf += fuzz_buf[i]

f = open('final.img', 'wb')
f.write(final_buf)
f.close()
