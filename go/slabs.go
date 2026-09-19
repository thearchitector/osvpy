package main

// Rows never move when a table grows. Only the small directory of slab
// pointers can be reallocated; each data allocation is bounded by slabSize.
const slabSize = 1024

type slabs[T any] struct {
	chunks []*[slabSize]T
	n      int
}

func (s *slabs[T]) Len() int { return s.n }
func (s *slabs[T]) At(i int) *T {
	if i < 0 || i >= s.n {
		panic("invalid index")
	}
	return &s.chunks[i/slabSize][i%slabSize]
}
func (s *slabs[T]) Append(v T) int {
	checked(s.n + 1)
	i := s.n
	if i%slabSize == 0 {
		s.chunks = append(s.chunks, new([slabSize]T))
	}
	s.chunks[i/slabSize][i%slabSize] = v
	s.n++
	return i
}
func (s *slabs[T]) Resize(n int) {
	checked(n)
	if n < s.n {
		s.Truncate(n)
		return
	}
	for len(s.chunks) < (n+slabSize-1)/slabSize {
		s.chunks = append(s.chunks, new([slabSize]T))
	}
	s.n = n
}

// Drop whole unused slabs after compaction. At most one slab of slack remains,
// with no final flattening or copy of the live rows.
func (s *slabs[T]) Truncate(n int) {
	if n < 0 || n > s.n {
		panic("invalid length")
	}
	count := (n + slabSize - 1) / slabSize
	clear(s.chunks[count:])
	s.chunks = s.chunks[:count]
	if count > 0 && n%slabSize != 0 {
		clear(s.chunks[count-1][n%slabSize:])
	}
	s.n = n
}
