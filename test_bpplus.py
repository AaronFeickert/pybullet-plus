import bpplus
from dumb25519 import random_point, random_scalar, Scalar
from random import randrange
import unittest

class TestBPPlus(unittest.TestCase):
	def test_complete(self):
		params = bpplus.RangeParameters(random_point(),random_point(),4) # last parameter is the bit length
		n_proofs = 3 # number of proofs to verify in a batch

		statements = []
		proofs = []
		masks = []
		for _ in range(n_proofs):
			# Generate the witness
			v = Scalar(randrange(0,2**params.N))
			r = random_scalar()
			masks.append(r)
			witness = bpplus.RangeWitness(v,r)

			# Generate the statement
			C = params.H*v + params.G*r
			seed = random_scalar()
			statement = bpplus.RangeStatement(params,C,seed)
			statements.append(statement)

			# Prove
			proof = bpplus.prove(statement,witness)
			proofs.append(proof)

		# Verify the entire batch
		masks_ = bpplus.verify(statements,proofs)
		self.assertEqual(masks,masks_)

if __name__ == '__main__':
	unittest.main()
