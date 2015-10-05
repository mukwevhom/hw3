/*
 * mm_alloc.c
 *
 * Stub implementations of the mm_* routines. Remove this comment and provide
 * a summary of your allocator's design here.
 */
#include "mm_alloc.h"
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
/* Your final implementation should comment out this macro. */
/* #define MM_USE_STUBS */
#define ASSERT     assert
#define align4(x)  (((((x)-1)>>2)<<2)+4)
#define TRUE 1
#define FALSE 0
                                                    
s_block_ptr base = NULL;            
s_block_ptr last;       
static s_block_ptr find_block(size_t size){  
  s_block_ptr p = base;
  for (; p != NULL; p = p->next){
      last = p;
      if (p->free && p->size >= size)         
          return p;                           
   }
  return NULL;                                
}

static s_block_ptr extend_heap(size_t t){
	int sb;
	s_block_ptr b;
	b=sbrk(0);
	sb= (int)sbrk(BLOCK_SIZE + t);
	if(sb < 0){
		return(NULL);
	}
	b->size = t;
	b->next = NULL;
	b->prev = last;
	b->ptr  = b->data;

	if(last)
		last->next = b;
		b->free = 0;
		return (b);             
}

void split_block(s_block_ptr p, size_t new_size){
    s_block_ptr new_block = NULL;              
    if (p->size >= new_size + S_BLOCK_SIZE + 4){

        p->size = new_size;  

        new_block = (s_block_ptr)(p->data + new_size);
        new_block->size = p->size - new_size - S_BLOCK_SIZE;
        new_block->ptr = new_block->data;
        new_block->free = TRUE;

        new_block->next = p->next;
        new_block->prev = p;
        if (p->next)
            p->next->prev = new_block;
        p->next = new_block;
    }
}

static s_block_ptr fusion_block(s_block_ptr pb){
    ASSERT(pb->free == TRUE); 

    if (pb->next && pb->next->free) 
    {
      pb->size = pb->size + BLOCK_SIZE + pb->next->size;
      if (pb->next->next)
        pb->next->next->prev = pb;
      pb->next = pb->next->next; 		
    }

    return (pb);
}


static s_block_ptr get_block(void *p){
    char *tmp;
    tmp = (char*)p;
    return (s_block_ptr)(tmp - BLOCK_SIZE);
}

static int is_valid_block_addr (void *p){
   s_block_ptr pb = get_block(p);
   if (base)
   {
     if(p > base && p < sbrk(0))
	return pb->ptr == p;
   }

   return FALSE;
}

static void copy_block(s_block_ptr src, s_block_ptr dst){
	int *sdata, *ddata; 
	size_t i;
	sdata = src->ptr;
	ddata = dst->ptr;
	for (i = 0; i * 4 < src->size && i * 4 < dst->size; i++)
		ddata[i] = sdata[i];
}

/*********************** Interfaces ***********************/
void* mm_malloc(size_t size)
{
#ifdef MM_USE_STUBS
    return calloc(1, size);
#else
    
    size_t t = align4(size);    
    s_block_ptr pb;

    
    if (base == NULL) 
    {
       pb = extend_heap(t);
       if (pb == NULL)
          return NULL;
       base = pb;
    }
    
    else 
    {
       
       pb = find_block(t);
       if (pb == NULL)
        {
          pb = extend_heap(t);
          if (pb == NULL)
            return NULL;
        }
       else
        {
          if (pb->size - t >= S_BLOCK_SIZE + 4)
            split_block(pb, t);
        }
    }
        
    pb->free = FALSE;
    return pb->ptr;
#endif
}

void* mm_realloc(void* ptr, size_t size)
{
#ifdef MM_USE_STUBS
    return realloc(ptr, size);
#else
    size_t t;
    void *newp;
    s_block_ptr pb, new;
    
    if (ptr == NULL)
        return mm_malloc(size);
    
    if ((pb=get_block(ptr)) != NULL){
        t = align4(size);
        if (pb->size >= t){
           if (pb->size - t >= (BLOCK_SIZE + 4))
		split_block(pb, t);
         }
    }
    else {
        if (pb->next && pb->next->free && (pb->size + BLOCK_SIZE + pb->next->size) >= t){
           fusion_block(pb);
           if (pb->size - t >= BLOCK_SIZE + 4)
 		split_block(pb, t);
        }
        else {
           newp = mm_malloc(t);
           if (newp == NULL)
               return NULL;
           new = get_block(newp);
           copy_block(pb, new);
           mm_free(pb);
           return (newp);  
        }
        return (pb);
    } 
    return (NULL);
#endif
}
void mm_free(void* ptr)
{
#ifdef MM_USE_STUBS
	free(ptr);
#else
	s_block_ptr pb;

	if ((pb=get_block(ptr)) != NULL){
		pb->free = TRUE;  

		if(pb->prev && pb->prev->free)
			fusion_block(pb->prev);

		if(pb->next)
			fusion_block(pb);

		else{
			if (pb->prev == NULL)
				base = NULL;
			else
				pb->prev->next = NULL;     
				brk(pb);
	}
}
    
#endif
}
