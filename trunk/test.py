import pyncap

n = pyncap.NCap(10000)
fd = n.AddIf("en0", "tcp or udp", True, [])

count = 0

def Output(x,y):
  global count
  print x,y

  count += 1
  if count >= 10:
    n.Stop()

print "Before Collect"
n.Collect(0, Output)
print "After Collect"
n.DropIf(fd)

