# Bulletproof+ range proof
#
# This implementation supports proof aggregation and batch verification.
# In the non-aggregated case, it also supports commitment mask recovery.
#
# It is a zero-knowledge proving system for the following relation:
# {(H,G,N,M),{C_j}_{j=0}^{M-1} ; {v_j,r_j}_{j=0}^{M-1} | for j = 0..M-1, 0 <= v_j < 2^N and C_j = v_j*H + r_j*G}
#
# Note that both `N` and `M` must powers of two.

import dumb25519
from dumb25519 import Point, Scalar, ScalarVector, PointVector, random_scalar, multiexp
from hashlib import blake2b
import transcript

class RangeParameters:
	def __init__(self,H,G,N,T,Gi,Hi):
		if not isinstance(H,Point):
			raise TypeError('Bad type for parameter H!')
		if not isinstance(G,PointVector):
			raise TypeError('Bad type for parameter G!')
		if not isinstance(N,int):
			raise TypeError('Bad type for parameter N!')
		if not isinstance(T,int) or T < 1:
			raise ValueError('Bad type or value for parameter T!')
		if not len(G) == T:
			raise ValueError('Bad size for parameter G!')
		if not isinstance(Gi,PointVector):
			raise ValueError('Bad type or value for parameter Gi!')
		if not isinstance(Hi,PointVector):
			raise ValueError('Bad type or value for parameter Hi!')
		if not len(Gi) == len(Hi):
			raise ValueError('Size mismatch for parameters Gi and Hi!')
		
		# Also need N to be a power of 2
		if  N < 1 or not (N & (N - 1)) == 0:
			raise ValueError('Bad value for parameter N!')
		
		self.H = H
		self.G = G
		self.N = N
		self.T = T
		self.Gi = Gi
		self.Hi = Hi

class RangeStatement:
	def __init__(self,params,C,seed=None):
		if not isinstance(params,RangeParameters):
			raise TypeError('Bad type for parameters!')
		if not isinstance(C,PointVector):
			raise TypeError('Bad type for range statement input C!')

		# Also need aggregation factor to be a power of 2
		M = len(C)
		if M < 1 or not (M & (M - 1)) == 0:
			raise ValueError('Bad value for parameter M!')
		
		# Need enough generators
		if len(params.Gi) < M*params.N:
			raise ValueError('Not enough generators for this statement!')
		
		# Mask recovery is only valid when M = 1
		if seed is not None and M > 1:
			raise ValueError('Mask recovery is not supported with this statement!')

		self.G = params.G
		self.H = params.H
		self.N = params.N
		self.T = params.T
		self.M = M
		self.Gi = params.Gi
		self.Hi = params.Hi
		self.C = C
		self.seed = seed

class CommitmentOpening:
	def __init__(self,v,r):
		if not isinstance(v,Scalar):
			raise TypeError('Bad type for commitment opening v!')
		if not isinstance(r,ScalarVector):
			raise TypeError('Bad type for commitment opening r!')
		
		self.v = v
		self.r = r

class RangeWitness:
	def __init__(self,openings):
		if not isinstance(openings,list):
			raise TypeError('Bad type for range witness!')
		T = 0
		for opening in openings:
			if not isinstance(opening,CommitmentOpening):
				raise TypeError('Bad type for range witness!')
			if T == 0:
				T = len(opening.r)
			else:
				if not len(opening.r) == T:
					raise ValueError('Bad value for range witness!')
		
		self.openings = openings

class RangeProof:
	def __init__(self,A,A1,B,r1,s1,d1,L,R):
		if not isinstance(A,Point):
			raise TypeError('Bad type for range proof element A!')
		if not isinstance(A1,Point):
			raise TypeError('Bad type for range proof element A1!')
		if not isinstance(B,Point):
			raise TypeError('Bad type for range proof element B!')
		if not isinstance(r1,Scalar):
			raise TypeError('Bad type for range proof element r1!')
		if not isinstance(s1,Scalar):
			raise TypeError('Bad type for range proof element s1!')
		if not isinstance(d1,ScalarVector):
			raise TypeError('Bad type for range proof element d1!')
		if not isinstance(L,PointVector):
			raise TypeError('Bad type for range proof element L!')
		if not isinstance(R,PointVector):
			raise TypeError('Bad type for range proof element R!')
		if not len(L) == len(R):
			raise IndexError('Range proof data length mismatch!')

		self.A = A
		self.A1 = A1
		self.B = B
		self.r1 = r1
		self.s1 = s1
		self.d1 = d1
		self.L = L
		self.R = R

# Data for a round of the inner product argument
class InnerProductRound:
	def __init__(self,Gi,Hi,G,H,a,b,alpha,y_powers,tr,seed):
		# Common data
		self.Gi = Gi
		self.Hi = Hi
		self.G = G
		self.H = H
		self.y_powers = y_powers
		self.done = False

		# Prover data
		self.a = a
		self.b = b
		self.alpha = alpha

		# Verifier data
		self.A = None
		self.B = None
		self.r1 = None
		self.s1 = None
		self.d1 = None
		self.L = PointVector([])
		self.R = PointVector([])

		# Transcript
		self.tr = tr

		# Seed for mask recovery
		self.round = 0
		self.seed = seed

# Produce mask-recovery nonces 
#
# INPUTS
#	seed: secret value shared by prover and verifier (Point)
#	label: identifier for the variable from the protocol (string)
#	j: index for multi-round values, if applicable (int or None)
#	k: index for multi-round values, if applicable (int or None)
# OUTPUTS
#	Scalar
# WARNING
#	The seed value must NEVER be reused across proofs, and should be effectively pseudorandom
def nonce(seed,label,j,k):
	# Check input sizes for compatibility with the Blake2b specification
	encoded_seed = str(seed).encode('utf-8')
	encoded_label = str(label).encode('utf-8')
	encoded_j = str(j).encode('utf-8') if j is not None else None
	encoded_k = str(j).encode('utf-8') if k is not None else None
	if len(encoded_seed) > blake2b.MAX_KEY_SIZE:
		raise TypeError('Nonce seed is too large!')
	if len(encoded_label) > blake2b.PERSON_SIZE:
		raise TypeError('Nonce label is too large!')
	if encoded_j is not None and len(encoded_j) > blake2b.SALT_SIZE:
		raise TypeError('Nonce index is too large!')

	if encoded_j is not None:	
		hasher = blake2b(digest_size=32,key=encoded_seed,person=encoded_label,salt=encoded_j)
	else:
		hasher = blake2b(digest_size=32,key=encoded_seed,person=encoded_label)

	# Produce a uniform Scalar output for the hash
	while True:
		if encoded_k is not None:
			hasher.update(encoded_k)
		result = hasher.hexdigest()
		if int(result,16) < dumb25519.l:
			return Scalar(int(result,16))
		
		# Update the hash with any fixed value to try again!
		hasher.update(b'0')

# Turn a scalar into a vector of bit scalars
#
# INPUTS
#   s: (Scalar)
#   N: number of bits (int)
# OUTPUTS
#   ScalarVector
def scalar_to_bits(s,N):
	result = []
	for i in range(N-1,-1,-1):
		if s/Scalar(1 << i) == Scalar(0):
			result.append(Scalar(0))
		else:
			result.append(Scalar(1))
			s -= Scalar(1 << i)
	return ScalarVector(list(reversed(result)))

# Perform an inner-product proof round
#
# INPUTS
#   data: round data (InnerProductRound)
def inner_product(data):
	n = len(data.Gi)
	T = len(data.alpha)

	if n == 1:
		data.done = True

		# Random masks
		r = random_scalar()
		s = random_scalar()
		d = [random_scalar() if data.seed is None else nonce(data.seed,'d',None,k) for k in range(T)]
		eta = [random_scalar() if data.seed is None else nonce(data.seed,'eta',None,k) for k in range(T)]

		data.A = data.Gi[0]*r + data.Hi[0]*s + data.H*(r*data.y_powers[1]*data.b[0] + s*data.y_powers[1]*data.a[0])
		data.B = data.H*(r*data.y_powers[1]*s)
		for k in range(T):
			data.A += data.G[k]*d[k]
			data.B += data.G[k]*eta[k]

		data.tr.update(data.A)
		data.tr.update(data.B)
		e = data.tr.challenge()

		data.r1 = r + data.a[0]*e
		data.s1 = s + data.b[0]*e
		data.d1 = ScalarVector([eta[k] + d[k]*e + data.alpha[k]*e**2 for k in range(T)])

		return

	n //= 2
	a1 = data.a[:n]
	a2 = data.a[n:]
	b1 = data.b[:n]
	b2 = data.b[n:]
	G1 = data.Gi[:n]
	G2 = data.Gi[n:]
	H1 = data.Hi[:n]
	H2 = data.Hi[n:]
	y_n_inverse = data.y_powers[n].invert()

	dL = [random_scalar() if data.seed is None else nonce(data.seed,'dL',data.round,k) for k in range(T)]
	dR = [random_scalar() if data.seed is None else nonce(data.seed,'dR',data.round,k) for k in range(T)]
	data.round += 1

	cL = Scalar(0)
	cR = Scalar(0)
	for i in range(n):
		cL += a1[i]*data.y_powers[i + 1]*b2[i]
		cR += a2[i]*data.y_powers[n + i + 1]*b1[i]
	
	# Compute L and R by multiscalar multiplication
	L_scalars = ScalarVector([cL])
	L_points = PointVector([data.H])
	R_scalars = ScalarVector([cR])
	R_points = PointVector([data.H])
	for k in range(T):
		L_scalars.append(dL[k])
		L_points.append(data.G[k])
		R_scalars.append(dR[k])
		R_points.append(data.G[k])
	for i in range(n):
		L_scalars.append(a1[i]*y_n_inverse)
		L_points.append(G2[i])
		L_scalars.append(b2[i])
		L_points.append(H1[i])
		R_scalars.append(a2[i]*data.y_powers[n])
		R_points.append(G1[i])
		R_scalars.append(b1[i])
		R_points.append(H2[i])
	data.L.append(multiexp(L_scalars, L_points))
	data.R.append(multiexp(R_scalars, R_points))

	data.tr.update(data.L[-1])
	data.tr.update(data.R[-1])
	e = data.tr.challenge()
	e_inverse = e.invert()

	data.Gi = G1*e_inverse + G2*(e*y_n_inverse)
	data.Hi = H1*e + H2*e_inverse

	data.a = a1*e + a2*data.y_powers[n]*e_inverse
	data.b = b1*e_inverse + b2*e
	data.alpha = ScalarVector([dL[k]*e**2 + data.alpha[k] + dR[k]*e_inverse**2 for k in range(T)])

# Generate a proof
def prove(statement,witness):
	if not isinstance(statement,RangeStatement):
		raise TypeError('Bad type for range statement!')
	if not isinstance(witness,RangeWitness):
		raise TypeError('Bad type for range witness!')
	
	# Check the statement validity
	M = len(statement.C)
	T = statement.T
	if not len(witness.openings) == M:
		raise ValueError('Invalid range statement!')
	if not len(statement.G) == T:
		raise ValueError('Not enough generators for this statement!')
	for j in range(M):
		C_ = statement.H*witness.openings[j].v
		for k in range(T):
			C_ += statement.G[k]*witness.openings[j].r[k]
		if not statement.C[j] == C_:
			raise ArithmeticError('Invalid range statement!')

	N = statement.N

	# Global generators
	G = statement.G
	H = statement.H
	Gi = statement.Gi[:N*M] # only use the necessary generators for this proof size
	Hi = statement.Hi[:N*M] # only use the necessary generators for this proof size

	tr = transcript.Transcript('Bulletproof+')
	tr.update(H)
	tr.update(G)
	tr.update(N)
	tr.update(T)
	tr.update(M)
	tr.update(Gi)
	tr.update(Hi)
	tr.update(statement.C)

	# Set bit arrays
	aL = ScalarVector([])
	aR = ScalarVector([])
	for j in range(M):
		bits = scalar_to_bits(witness.openings[j].v, N)
		aL.extend(bits)
		aR.extend(ScalarVector([bit - Scalar(1) for bit in bits]))

	# Compute A by multiscalar multiplication
	alpha = ScalarVector([random_scalar() if statement.seed is None else nonce(statement.seed,'alpha',None,k) for k in range(T)])
	A_scalars = ScalarVector([])
	A_points = PointVector([])
	for k in range(T):
		A_scalars.append(alpha[k])
		A_points.append(G[k])
	for i in range(N*M):
		A_scalars.append(aL[i])
		A_points.append(Gi[i])
		A_scalars.append(aR[i])
		A_points.append(Hi[i])
	A = multiexp(A_scalars, A_points)

	# Get challenges
	tr.update(A)
	y = tr.challenge()
	z = tr.challenge()
	z_square = z**2

	# Compute powers of the challenge
	y_powers = ScalarVector([Scalar(1)])
	for _ in range(1, M*N + 2):
		y_powers.append(y_powers[-1]*y)

	# Compute d efficiently
	d = ScalarVector([z_square])
	for i in range(1, N):
		d.append(Scalar(2)*d[i-1])
	for j in range(1, M):
		for i in range(N):
			d.append(d[(j-1)*N + i]*z_square)

	# Prepare for inner product
	aL1 = aL - ScalarVector([z for _ in range(N*M)])
	aR1 = aR + ScalarVector([d[i]*y_powers[N*M - i] + z for i in range(N*M)])
	alpha1 = ScalarVector([alpha[k] for k in range(T)])
	z_even_powers = 1
	for j in range(M):
		z_even_powers *= z_square
		for k in range(T):
			alpha1[k] += z_even_powers*witness.openings[j].r[k]*y_powers[N*M + 1]

	# Initial inner product inputs
	ip_data = InnerProductRound(Gi,Hi,G,H,aL1,aR1,alpha1,y_powers,tr,statement.seed)
	while True:
		inner_product(ip_data)

		# We have reached the end of the recursion
		if ip_data.done:
			return RangeProof(A,ip_data.A,ip_data.B,ip_data.r1,ip_data.s1,ip_data.d1,ip_data.L,ip_data.R)

# Verify a batch of proofs
def verify(statements,proofs):
	# Check statement consistency
	G = None
	H = None
	N = None
	T = None
	max_MN = None
	Gi = None
	Hi = None

	if not len(statements) == len(proofs):
		raise IndexError('Range statement/proof length mismatch!')

	# Set common statement values
	for statement in statements:
		if not isinstance(statement,RangeStatement):
			raise TypeError('Bad type for range statement!')

		if G is not None and statement.G != G:
			raise ValueError('Inconsistent range batch statements!')
		else:
			G = statement.G

		if H is not None and statement.H != H:
			raise ValueError('Inconsistent range batch statements!')
		else:
			H = statement.H

		if N is not None and statement.N != N:
			raise ValueError('Inconsistent range batch statements!')
		else:
			N = statement.N

		if T is not None and statement.T != T:
			raise ValueError('Inconsistent range batch statements!')
		else:
			T = statement.T

		if max_MN is None or len(statement.C)*statement.N > max_MN:
			max_MN = len(statement.C)*statement.N
			Gi = statement.Gi
			Hi = statement.Hi
	
	# Confirm we have valid statement values
	if G is None or H is None or N is None or T is None or max_MN is None or Gi is None or Hi is None:
		raise ValueError('Bad range batch statement!')
		
	for proof in proofs:
		if not isinstance(proof,RangeProof):
			raise TypeError('Bad type for range proof!')
	
	# Compute log2(N)
	log_N = 0
	temp_N = N >> 1
	while temp_N != 0:
		log_N += 1
		temp_N >>= 1

	# Compute 2**N-1 for later use
	TWO_N_MINUS_ONE = Scalar(2)
	for i in range(log_N):
		TWO_N_MINUS_ONE *= TWO_N_MINUS_ONE
	TWO_N_MINUS_ONE -= Scalar(1)

	# Weighted coefficients for common generators
	G_scalar = ScalarVector([Scalar(0) for _ in range(T)])
	H_scalar = Scalar(0)
	Gi_scalars = ScalarVector([Scalar(0)]*max_MN)
	Hi_scalars = ScalarVector([Scalar(0)]*max_MN)

	# Final multiscalar multiplication data
	scalars = ScalarVector([])
	points = PointVector([])

	# Recovered masks
	masks = []

	# Process each proof and add it to the batch
	for index,proof in enumerate(proofs):
		C = statements[index].C
		seed = statements[index].seed
		A = proof.A
		A1 = proof.A1
		B = proof.B
		r1 = proof.r1
		s1 = proof.s1
		d1 = proof.d1
		L = proof.L
		R = proof.R

		if not len(L) == len(R):
			raise IndexError
		if not 1 << len(L) == len(C)*N:
			raise IndexError
		
		# Helper values
		M = len(C)
		rounds = len(L)
		
		# Batch weight
		weight = random_scalar()
		if weight == Scalar(0):
			raise ArithmeticError

		# Start transcript
		tr = transcript.Transcript('Bulletproof+')
		tr.update(H)
		tr.update(G)
		tr.update(N)
		tr.update(T)
		tr.update(M)
		tr.update(Gi[:N*M])
		tr.update(Hi[:N*M])
		tr.update(C)

		# Reconstruct challenges
		tr.update(proof.A)
		y = tr.challenge()
		if y == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')
		z = tr.challenge()
		if z == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')

		challenges = ScalarVector([]) # round challenges
		for j in range(rounds):
			tr.update(L[j])
			tr.update(R[j])
			challenges.append(tr.challenge())
			if challenges[j] == Scalar(0):
				raise ArithmeticError('Bad verifier challenge!')
		challenges_inv = challenges.invert()
		tr.update(A1)
		tr.update(B)
		e = tr.challenge()
		if e == Scalar(0):
			raise ArithmeticError('Bad verifier challenge!')

		# Compute useful challenge values
		z_square = z**2
		e_square = e**2
		y_inverse = y.invert()

		y_NM = y
		for j in range(rounds):
			y_NM *= y_NM

		y_NM_1 = y_NM*y

		y_sum = Scalar(0)
		y_sum_temp = y
		for i in range(N*M):
			y_sum += y_sum_temp
			y_sum_temp *= y
		
		# Compute d efficiently
		d = ScalarVector([z_square])
		for i in range(1, N):
			d.append(Scalar(2)*d[i-1])
		for j in range(1, M):
			for i in range(N):
				d.append(d[(j-1)*N + i]*z_square)
		
		# Compute its sum efficiently
		d_sum = z_square
		d_sum_temp_z = z_square
		d_sum_temp_2M = 2*M
		while d_sum_temp_2M > 2:
			d_sum += d_sum*d_sum_temp_z
			d_sum_temp_z *= d_sum_temp_z
			d_sum_temp_2M //= 2
		d_sum *= TWO_N_MINUS_ONE

		# Recover the masks if possible (only for non-aggregated proofs)
		if M == 1 and seed is not None:
			mask = ScalarVector([])
			for k in range(T):
				temp = (d1[k] - nonce(seed,'eta',None,k) - e*nonce(seed,'d',None,k))*e.invert()**2
				temp -= nonce(seed,'alpha',None,k)
				for j in range(rounds):
					temp -= challenges[j]**2*nonce(seed,'dL',j,k)
					temp -= challenges_inv[j]**2*nonce(seed,'dR',j,k)
				temp *= (z_square*y_NM_1).invert()

				mask.append(temp)

			masks.append(mask)
		else:
			masks.append(None)

		# Aggregate the generator scalars
		s = ScalarVector([Scalar(1)])
		for j in range(rounds):
			s[0] *= challenges_inv[j]
		
		for i in range(1,M*N):
			lg_i = 32 - 1 - "{:032b}".format(i).index("1")
			k = 1 << lg_i
			u_lg_i_sq = challenges[rounds - 1 - lg_i]**2
			print(i,lg_i,rounds-1-lg_i)
			s.append(s[i - k] * u_lg_i_sq)

		y_inv_i = Scalar(1)
		y_NM_i = y_NM
		for i in range(M*N):
			g = r1*e*y_inv_i
			h = s1*e

			g *= s[i]
			h *= s[-i-1]
					
			Gi_scalars[i] += weight*(g + e**2*z)
			Hi_scalars[i] += weight*(h - e**2*(d[i]*y_NM_i+z))

			y_inv_i *= y_inverse
			y_NM_i *= y_inverse

		# Remaining terms
		z_even_powers = Scalar(1)
		for j in range(M):
			z_even_powers *= z_square
			scalars.append(weight*(-e_square*z_even_powers*y_NM_1))
			points.append(C[j])

		H_scalar += weight*(r1*y*s1 + e_square*(y_NM_1*z*d_sum + (z**2-z)*y_sum))
		G_scalar = ScalarVector([G_scalar[k] + weight*d1[k] for k in range(T)])

		scalars.append(weight*-e)
		points.append(A1)
		scalars.append(-weight)
		points.append(B)
		scalars.append(weight*-e_square)
		points.append(A)

		for j in range(rounds):
			scalars.append(weight*(-e_square*challenges[j]**2))
			points.append(L[j])
			scalars.append(weight*(-e_square*challenges_inv[j]**2))
			points.append(R[j])

	# Common generators
	for k in range(T):
		scalars.append(G_scalar[k])
		points.append(G[k])
	scalars.append(H_scalar)
	points.append(H)
	for i in range(max_MN):
		scalars.append(Gi_scalars[i])
		points.append(Gi[i])
		scalars.append(Hi_scalars[i])
		points.append(Hi[i])

	if not multiexp(scalars,points) == dumb25519.Z:
		raise ArithmeticError('Failed verification!')
	
	return masks
