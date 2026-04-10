const prisma = require('../config/prisma');

// Initialize Default Chart of Accounts for a Company
const initializeChartOfAccounts = async (companyId) => {
    try {
        // 1. Verify Company exists
        const company = await prisma.company.findUnique({
            where: { id: companyId }
        });

        if (!company) {
            return {
                success: false,
                message: `Company with ID ${companyId} not found. Please logout and login again.`
            };
        }

        // 2. Check if already initialized
        const existing = await prisma.accountgroup.findFirst({
            where: { companyId, name: 'Assets' }
        });

        if (existing) {
            return {
                success: true,
                message: 'Chart of Accounts already initialized'
            };
        }

        // Create Primary Account Groups
        const assets = await prisma.accountgroup.create({
            data: {
                name: 'Assets',
                type: 'ASSETS',
                companyId: companyId
            }
        });

        const liabilities = await prisma.accountgroup.create({
            data: {
                name: 'Liabilities',
                type: 'LIABILITIES',
                companyId: companyId
            }
        });

        const income = await prisma.accountgroup.create({
            data: {
                name: 'Income',
                type: 'INCOME',
                companyId: companyId
            }
        });

        const expenses = await prisma.accountgroup.create({
            data: {
                name: 'Expenses',
                type: 'EXPENSES',
                companyId: companyId
            }
        });

        const equity = await prisma.accountgroup.create({
            data: {
                name: 'Equity',
                type: 'EQUITY',
                companyId: companyId
            }
        });

        // Create Sub Groups under Assets
        const cash = await prisma.accountsubgroup.create({
            data: {
                name: 'Cash',
                groupId: assets.id,
                companyId: companyId
            }
        });

        const bank = await prisma.accountsubgroup.create({
            data: {
                name: 'Bank',
                groupId: assets.id,
                companyId: companyId
            }
        });

        const accountsReceivable = await prisma.accountsubgroup.create({
            data: {
                name: 'Accounts Receivable',
                groupId: assets.id,
                companyId: companyId
            }
        });

        // Create Sub Groups under Liabilities
        const accountsPayable = await prisma.accountsubgroup.create({
            data: {
                name: 'Accounts Payable',
                groupId: liabilities.id,
                companyId: companyId
            }
        });

        // Create Sub Groups under Income
        const salesIncome = await prisma.accountsubgroup.create({
            data: {
                name: 'Sales Income',
                groupId: income.id,
                companyId: companyId
            }
        });

        const serviceIncome = await prisma.accountsubgroup.create({
            data: {
                name: 'Service Income',
                groupId: income.id,
                companyId: companyId
            }
        });

        const otherIncome = await prisma.accountsubgroup.create({
            data: {
                name: 'Other Income',
                groupId: income.id,
                companyId: companyId
            }
        });

        // Create Sub Groups under Expenses
        const directExpenses = await prisma.accountsubgroup.create({
            data: {
                name: 'Direct Expenses',
                groupId: expenses.id,
                companyId: companyId
            }
        });

        const indirectExpenses = await prisma.accountsubgroup.create({
            data: {
                name: 'Indirect Expenses',
                groupId: expenses.id,
                companyId: companyId
            }
        });

        // Create Default Ledgers
        await prisma.ledger.create({
            data: {
                name: 'Cash in Hand',
                groupId: assets.id,
                subGroupId: cash.id,
                companyId: companyId,
                openingBalance: 0,
                currentBalance: 0
            }
        });

        await prisma.ledger.create({
            data: {
                name: 'Inventory Asset',
                groupId: assets.id,
                companyId: companyId,
                openingBalance: 0,
                currentBalance: 0
            }
        });

        await prisma.ledger.create({
            data: {
                name: 'Cost of Goods Sold',
                groupId: expenses.id,
                subGroupId: directExpenses.id,
                companyId: companyId,
                openingBalance: 0,
                currentBalance: 0
            }
        });

        await prisma.ledger.create({
            data: {
                name: 'Inventory Adjustment Expense',
                groupId: expenses.id,
                subGroupId: indirectExpenses.id,
                companyId: companyId,
                openingBalance: 0,
                currentBalance: 0
            }
        });

        await prisma.ledger.create({
            data: {
                name: 'Opening Balance Equity',
                groupId: equity.id,
                companyId: companyId,
                openingBalance: 0,
                currentBalance: 0
            }
        });

        return {
            success: true,
            message: 'Chart of Accounts initialized successfully'
        };
    } catch (error) {
        console.error('Error initializing COA:', error);
        throw error;
    }
};

// Get Chart of Accounts
const getChartOfAccounts = async (companyId, filters = {}) => {
    try {
        const { startDate, endDate, search } = filters;

        // Base filter for ledgers
        const ledgerWhere = {
            ...(search ? { name: { contains: search } } : {}),
            ...(startDate || endDate ? {
                createdAt: {
                    ...(startDate ? { gte: new Date(startDate) } : {}),
                    ...(endDate ? { lte: new Date(endDate) } : {})
                }
            } : {})
        };

        const groups = await prisma.accountgroup.findMany({
            where: { companyId },
            include: {
                accountsubgroup: {
                    include: {
                        ledger: {
                            where: {
                                ...ledgerWhere
                            },
                            include: {
                                ledger: true
                            }
                        }
                    }
                },
                ledger: {
                    where: {
                        subGroupId: null,
                        ...ledgerWhere
                    },
                    include: {
                        ledger: true
                    }
                }
            },
            orderBy: { type: 'asc' }
        });

        return groups;
    } catch (error) {
        console.error('Error fetching COA:', error);
        throw error;
    }
};

// Create Account Group
const createAccountGroup = async (data) => {
    try {
        const group = await prisma.accountgroup.create({
            data: {
                name: data.name,
                type: data.type,
                companyId: data.companyId
            }
        });

        return group;
    } catch (error) {
        console.error('Error creating account group:', error);
        throw error;
    }
};

// Create Account Sub Group
const createAccountSubGroup = async (data) => {
    try {
        const subGroup = await prisma.accountsubgroup.create({
            data: {
                name: data.name,
                groupId: data.groupId,
                companyId: data.companyId
            }
        });

        return subGroup;
    } catch (error) {
        console.error('Error creating account sub group:', error);
        throw error;
    }
};

// Helper to map frontend account types to backend AccountGroup types
const resolveGroupType = (accountType) => {
    const typeMap = {
        'current_asset': 'ASSETS',
        'inventory_asset': 'ASSETS',
        'non_current_asset': 'ASSETS',
        'current_liability': 'LIABILITIES',
        'long_term_liability': 'LIABILITIES',
        'share_capital': 'LIABILITIES',
        'retained_earnings': 'LIABILITIES',
        'owners_equity': 'EQUITY',
        'sales_revenue': 'INCOME',
        'other_revenue': 'INCOME',
        'inventory_gain': 'INCOME',
        'cogs': 'EXPENSES',
        'payroll': 'EXPENSES',
        'general': 'EXPENSES'
    };
    return typeMap[accountType] || null;
};

// Create Ledger
const createLedger = async (data) => {
    try {
        let groupId = data.groupId;

        // Logic to automatically resolve groupId if not provided
        if (!groupId) {
            // Priority: Derive from Account Type (Parent Logic Removed by User Request)
            if (data.accountType) {
                const groupType = resolveGroupType(data.accountType);
                if (groupType) {
                    const group = await prisma.accountgroup.findFirst({
                        where: {
                            companyId: data.companyId,
                            type: groupType
                        }
                    });
                    if (group) {
                        groupId = group.id;
                    } else {
                        console.log(`Debug COA: Group not found. CompanyID: ${data.companyId}, Type: ${groupType}`);
                        // Fallback: Try loose name match if enum types mismatched
                        const looseGroup = await prisma.accountgroup.findFirst({
                            where: { companyId: data.companyId, name: { contains: groupType === 'EXPENSES' ? 'Expense' : groupType } }
                        });
                        if (looseGroup) groupId = looseGroup.id;
                    }
                }
            }
        }

        if (!groupId) {
            throw new Error(`Could not resolve Account Group. Please provide valid Account Type. (Debug: Type=${data.accountType || 'None'})`);
        }

        const ledger = await prisma.ledger.create({
            data: {
                id: data.id, // Optional: will only work if ID is not auto-increment or identity insert allowed/handled by logic
                name: data.name,
                groupId: groupId,
                subGroupId: data.subGroupId,
                companyId: data.companyId,
                openingBalance: data.openingBalance || 0,
                currentBalance: data.openingBalance || 0,
                isControlAccount: data.isControlAccount || false,
                isEnabled: data.isEnabled !== undefined ? data.isEnabled : true,
                description: data.description,
                parentLedgerId: data.parentLedgerId ? parseInt(data.parentLedgerId) : null,
                updatedAt: new Date()
            }
        });

        return ledger;
    } catch (error) {
        console.error('Error creating ledger:', error);
        throw error;
    }
};

// Get Ledger by ID
const getLedgerById = async (id, companyId) => {
    try {
        const ledger = await prisma.ledger.findFirst({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            include: {
                accountgroup: true,
                accountsubgroup: true,
                ledger: true,
                other_ledger: true,
                transaction_transaction_creditLedgerIdToledger: {
                    include: {
                        ledger_transaction_creditLedgerIdToledger: true
                    }
                },
                transaction_transaction_debitLedgerIdToledger: {
                    include: {
                        ledger_transaction_debitLedgerIdToledger: true
                    }
                }
            }
        });

        return ledger;
    } catch (error) {
        console.error('Error fetching ledger:', error);
        throw error;
    }
};

// Get Ledger Transactions
const getLedgerTransactions = async (ledgerId, companyId) => {
    try {
        const transactions = await prisma.transaction.findMany({
            where: {
                companyId: companyId,
                OR: [
                    { debitLedgerId: parseInt(ledgerId) },
                    { creditLedgerId: parseInt(ledgerId) }
                ]
            },
            include: {
                ledger_transaction_debitLedgerIdToledger: true,
                ledger_transaction_creditLedgerIdToledger: true,
                invoice: {
                    include: { customer: true }
                },
                purchasebill: {
                    include: { vendor: true }
                },
                receipt: {
                    include: { customer: true }
                },
                payment: {
                    include: { vendor: true }
                }
            },
            orderBy: { date: 'desc' }
        });

        return transactions;
    } catch (error) {
        console.error('Error fetching ledger transactions:', error);
        throw error;
    }
};

// Update Ledger Balance
const updateLedgerBalance = async (ledgerId, amount, isDebit) => {
    try {
        const ledger = await prisma.ledger.findUnique({
            where: { id: ledgerId }
        });

        const newBalance = isDebit
            ? ledger.currentBalance + amount
            : ledger.currentBalance - amount;

        await prisma.ledger.update({
            where: { id: ledgerId },
            data: { currentBalance: newBalance, updatedAt: new Date() }
        });

        return newBalance;
    } catch (error) {
        console.error('Error updating ledger balance:', error);
        throw error;
    }
};

// Get Account Group by ID
const getAccountGroupById = async (id, companyId) => {
    try {
        const group = await prisma.accountgroup.findFirst({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            include: {
                accountsubgroup: {
                    include: {
                        ledger: true
                    }
                },
                ledger: {
                    where: {
                        subGroupId: null
                    }
                }
            }
        });

        return group;
    } catch (error) {
        console.error('Error fetching account group:', error);
        throw error;
    }
};

// Update Account Group
const updateAccountGroup = async (id, companyId, data) => {
    try {
        const group = await prisma.accountgroup.updateMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            data: {
                name: data.name,
                type: data.type,
                updatedAt: new Date()
            }
        });

        if (group.count === 0) {
            throw new Error('Account group not found or no changes made');
        }

        return await prisma.accountgroup.findUnique({
            where: { id: parseInt(id) }
        });
    } catch (error) {
        console.error('Error updating account group:', error);
        throw error;
    }
};

// Delete Account Group
const deleteAccountGroup = async (id, companyId) => {
    try {
        const result = await prisma.accountgroup.deleteMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            }
        });

        if (result.count === 0) {
            throw new Error('Account group not found');
        }

        return true;
    } catch (error) {
        console.error('Error deleting account group:', error);
        throw error;
    }
};

// Get Account Sub Group by ID
const getAccountSubGroupById = async (id, companyId) => {
    try {
        const subGroup = await prisma.accountsubgroup.findFirst({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            include: {
                accountgroup: true,
                ledger: true
            }
        });

        return subGroup;
    } catch (error) {
        console.error('Error fetching account sub-group:', error);
        throw error;
    }
};

// Update Account Sub Group
const updateAccountSubGroup = async (id, companyId, data) => {
    try {
        const subGroup = await prisma.accountsubgroup.updateMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            data: {
                name: data.name,
                groupId: parseInt(data.groupId),
                updatedAt: new Date()
            }
        });

        if (subGroup.count === 0) {
            throw new Error('Account sub-group not found or no changes made');
        }

        return await prisma.accountsubgroup.findUnique({
            where: { id: parseInt(id) },
            include: { accountgroup: true }
        });
    } catch (error) {
        console.error('Error updating account sub-group:', error);
        throw error;
    }
};

// Delete Account Sub Group
const deleteAccountSubGroup = async (id, companyId) => {
    try {
        const result = await prisma.accountsubgroup.deleteMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            }
        });

        if (result.count === 0) {
            throw new Error('Account sub-group not found');
        }

        return true;
    } catch (error) {
        console.error('Error deleting account sub-group:', error);
        throw error;
    }
};

// Get All Ledgers
const getAllLedgers = async (companyId) => {
    try {
        const ledgers = await prisma.ledger.findMany({
            where: { companyId },
            include: {
                accountgroup: true,
                accountsubgroup: true,
                ledger: true
            },
            orderBy: { name: 'asc' }
        });

        return ledgers;
    } catch (error) {
        console.error('Error fetching ledgers:', error);
        throw error;
    }
};

// Update Ledger
const updateLedger = async (id, companyId, data) => {
    try {
        const ledger = await prisma.ledger.updateMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            },
            data: {
                name: data.name,
                groupId: data.groupId,
                subGroupId: data.subGroupId,
                openingBalance: data.openingBalance,
                isControlAccount: data.isControlAccount,
                isEnabled: data.isEnabled,
                description: data.description,
                parentLedgerId: data.parentLedgerId ? parseInt(data.parentLedgerId) : null,
                updatedAt: new Date()
            }
        });

        if (ledger.count === 0) {
            throw new Error('Ledger not found or no changes made');
        }

        return await prisma.ledger.findUnique({
            where: { id: parseInt(id) },
            include: {
                accountgroup: true,
                accountsubgroup: true,
                ledger: true
            }
        });
    } catch (error) {
        console.error('Error updating ledger:', error);
        throw error;
    }
};

// Delete Ledger
const deleteLedger = async (id, companyId) => {
    try {
        const result = await prisma.ledger.deleteMany({
            where: {
                id: parseInt(id),
                companyId: companyId
            }
        });

        if (result.count === 0) {
            throw new Error('Ledger not found');
        }

        return true;
    } catch (error) {
        console.error('Error deleting ledger:', error);
        throw error;
    }
};

module.exports = {
    initializeChartOfAccounts,
    getChartOfAccounts,
    createAccountGroup,
    createAccountSubGroup,
    createLedger,
    getLedgerById,
    getLedgerTransactions,
    updateLedgerBalance,
    getAccountGroupById,
    updateAccountGroup,
    deleteAccountGroup,
    getAccountSubGroupById,
    updateAccountSubGroup,
    deleteAccountSubGroup,
    getAllLedgers,
    updateLedger,
    deleteLedger
};
