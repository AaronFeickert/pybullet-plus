import bpplus
from dumb25519 import random_point, random_scalar, Scalar, ScalarVector,PointVector
from random import randrange
import unittest

class TestBPPlus(unittest.TestCase):
	def test_complete(self):
		N = 4 # bit length
		M = [1, 2] # aggregation factor for each proof in a batch

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
			openings = []
			for i in range(M[j]):
				v = Scalar(randrange(1 << params.N))
				r = random_scalar()
				openings.append(bpplus.CommitmentOpening(v,r))
				if i == 0:
					masks.append(r if M[j] == 1 else None)
			witness = bpplus.RangeWitness(openings)

			# Generate the statement
			C = PointVector([params.H*openings[i].v + params.G*openings[i].r for i in range(M[j])])
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
		M = [1, 2] # aggregation factor for each proof in a batch

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
			openings = []
			for _ in range(M[j]):
				v = Scalar(randrange(1 << params.N))
				r = random_scalar()
				openings.append(bpplus.CommitmentOpening(v,r))
				masks.append(r if M[j] == 1 else None)
			witness = bpplus.RangeWitness(openings)

			# Generate the statement
			C = PointVector([params.H*openings[i].v + params.G*openings[i].r for i in range(M[j])])
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
