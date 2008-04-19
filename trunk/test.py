import pyncap

n = pyncap.NCap(10000)
fd = n.AddIf("en0", "tcp", False, [])
n.DropIf(fd)
