#ifdef __cplusplus
extern "C" {
#endif

#define MUTATE      0
#define GENERATE    1

extern uint32_t mutate_args_init(uint8_t* seed,uint32_t len);
extern uint32_t mutate_args(uint8_t* buf, uint32_t buf_size);
extern void mutate_args_fini(void);

extern void mutate_havoc_init(uint8_t* seed,uint32_t len, uint32_t stage_max);
extern uint32_t mutate_havoc(uint8_t* buf, uint32_t buf_size, int option);
extern void mutate_havoc_fini(void);




#ifdef __cplusplus
}
#endif
