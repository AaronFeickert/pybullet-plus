import bpplus
from dumb25519 import random_point, random_scalar, Scalar, PointVector
from random import randrange
import unittest

class TestBPPlus(unittest.TestCase):
	def test_complete(self):
		N = 4 # bit length
		n_proofs = 3 # number of proofs to verify in a batch

		# Produce generators at random; in practice these would be public and reproducible
		H = random_point()
		G = random_point()
		Gi = PointVector([random_point() for _ in range(N)])
		Hi = PointVector([random_point() for _ in range(N)])
		params = bpplus.RangeParameters(H,G,N,Gi,Hi)

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

	def test_evil_seed(self):
		N = 4 # bit length
		n_proofs = 3 # number of proofs to verify in a batch

		# Produce generators at random; in practice these would be public and reproducible
		H = random_point()
		G = random_point()
		Gi = PointVector([random_point() for _ in range(N)])
		Hi = PointVector([random_point() for _ in range(N)])
		params = bpplus.RangeParameters(H,G,N,Gi,Hi)

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
		
		# Use an evil seed for one of the proofs
		statements[0].seed = random_scalar()

		# Verify the entire batch
		masks_ = bpplus.verify(statements,proofs)

		# The mask corresponding to the evil seed should not match
		self.assertNotEqual(masks[0],masks_[0])
		for i in range(1,n_proofs):
			self.assertEqual(masks[i],masks_[i])

if __name__ == '__main__':
	unittest.main()
