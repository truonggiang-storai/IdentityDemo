using Identity.Application.Interfaces;
using Identity.Infrastructure.Database.Contexts;

namespace Identity.Infrastructure.Database.DataRepositories
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly AppDbContext _dbContext;

        public UnitOfWork(AppDbContext dbContext) 
        {
            _dbContext = dbContext;
        }

        public async Task CompleteAsync()
        {
            await _dbContext.SaveChangesAsync();
        }
    }
}
