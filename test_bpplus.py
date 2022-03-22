import bpplus
from dumb25519 import random_point, random_scalar, Scalar, ScalarVector,PointVector
from random import randrange
import unittest

class TestBPPlus(unittest.TestCase):
	def test_complete(self):
		N = 4 # bit length
		M = [1, 2, 4] # aggregation factor for each proof in a batch

		# Produce generators at random; in practice these would be public and reproducible
		H = random_point()
		G = random_point()
		Gi = PointVector([random_point() for _ in range(max(M)*N)])
		Hi = PointVector([random_point() for _ in range(max(M)*N)])
		params = bpplus.RangeParameters(H,G,N,Gi,Hi)

		statements = []
		proofs = []
		masks = []
		for j in range(len(M)):
			# Generate the witness
			v = ScalarVector([Scalar(randrange(0,2**params.N)) for _ in range(M[j])])
			r = ScalarVector([random_scalar() for _ in range(M[j])])
			masks.append(r[0] if M[j] == 1 else None)
			witness = bpplus.RangeWitness(v,r)

			# Generate the statement
			C = PointVector([params.H*v[j] + params.G*r[j] for j in range(M[j])])
			seed = random_scalar() if M[j] == 1 else None
			statement = bpplus.RangeStatement(params,C,seed)
			statements.append(statement)

			# Prove
			proof = bpplus.prove(statement,witness)
			proofs.append(proof)

		# Verify the entire batch
		masks_ = bpplus.verify(statements,proofs)
		self.assertEqual(masks,masks_)

	def test_bad_batch(self):
		N = 4 # bit length
		M = [1, 2, 4] # aggregation factor for each proof in a batch

		# Produce generators at random; in practice these would be public and reproducible
		H = random_point()
		G = random_point()
		Gi = PointVector([random_point() for _ in range(max(M)*N)])
		Hi = PointVector([random_point() for _ in range(max(M)*N)])
		params = bpplus.RangeParameters(H,G,N,Gi,Hi)

		statements = []
		proofs = []
		masks = []
		for j in range(len(M)):
			# Generate the witness
			v = ScalarVector([Scalar(randrange(0,2**params.N)) for _ in range(M[j])])
			r = ScalarVector([random_scalar() for _ in range(M[j])])
			masks.append(r[0] if M[j] == 1 else None)
			witness = bpplus.RangeWitness(v,r)

			# Generate the statement
			C = PointVector([params.H*v[j] + params.G*r[j] for j in range(M[j])])
			seed = random_scalar() if M[j] == 1 else None
			statement = bpplus.RangeStatement(params,C,seed)
			statements.append(statement)

			# Prove
			proof = bpplus.prove(statement,witness)
			proofs.append(proof)
		
		# Make one of the proofs invalid
		proofs[0].A = random_point()

		# Verify the entire batch
		with self.assertRaises(ArithmeticError):
			bpplus.verify(statements,proofs)

if __name__ == '__main__':
	unittest.main()
