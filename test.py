#
# Simple testing program for pyncap
#
import pyncap

n = pyncap.NCap(10000)
fd = n.AddIf("lo0", "tcp or udp", True, [])
print n.DropFd(100)
print n.LastError()

fp = open('/tmp/ncap.out', 'w')
count = 0

def Output(x, ncap):
  global count
  global fp
  global n
  
  print x, ncap

  n.Write(ncap, fp)
  
  count += 1
  if count >= 10:
    n.Stop()

print "Before Collect"
n.Collect(0, Output)
print "After Collect"
n.DropIf(fd)

